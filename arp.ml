(*
   We want to represent a partial function:
   IP_addr -> MAC_addr
   But the evaluation of this function is weird: we don't have all of its
   graph at the same time. Moreover, its value can vary over time, as hosts
   join and leave the network.

   Ideas:
   - If we cannot complete the evaluation, then just return None and have the
   client try again in the future. In the mean time, we will try and obtain a
   value from the network. This is the behaviour suggested by RFC826, under
   "Packet Generation".
   - If we cannot complete the evaluation, then return immediately to the client
   with a subscription to a waiting list that will be advised as soon as we have
   a value (or will timeout). This is the approach currently used in Mirage (but
   excluding timeouts).
   - Block until we can complete the evaluation (or time out). Blocking at this
   level would not be ideal.
   - Instead of broadcasting a request, we could first try querying the
   last-known-host with that address (if we know of one).

   In each case, what's persistent, and what's transient?
   - Persistent: current config of the database:
       * mappings from IPs to MACs
       * also IP addresses we have bound to the interface?
       * Other?
         Also include waiting lists?
         Also, what needs to be done in case db is reloaded?
          This reduces to figuring out what to do in case a MAC address for an IP
            address is updated. Do we go back in time and tell every past caller?
            Or do we rely on them to recheck?
            This is not really needed, since we expire values based on age.
            So in the worst case, we would start with an empty database.
   - Transient: timeouts of lookups, ages of values, and associated state.

  How is all this different from the state info that's kept at other layers in
   the network stack? To be determined...
*)

(*NOTE this implementation is specialised for Ethernet and IP,
  i.e., using the language of RFC826 I'm assuming that
  ar$pro={ether_type$DOD_INTERNET} and ar$hrd={ares_hrd$Ethernet}.
  Consequently, it should always be the case that ar$hln=6 (bytes) and ar$pln=4.
*)

(*NOTE I'm assuming that ethernet packet has been parsed according to the
  "Packet format" section of RFC826. For ARP code to be run, the Protocol Type
  field of the Ethernet packet header must be ether_type$ADDRESS_RESOLUTION.
*)

(*NOTE on overall behaviour, based on RFC826:
  - We assume that source-related info is correct. (That is, we assume that
  nobody on the network might be spoofing.)
  - The ares_op$REPLY opcode has a rather passive semantics, in the sense that
  it only seems to serve to avoid a reply from being sent (as would be the case
  if the ares_op$REQUEST opcode were used) from the targe.
  - A host isregards replies&requests targetted at others, unless the
  reply/request relates to a mapping for an address that's in its ARP table.
*)

(*NOTE from RFC826:
"The protocol described in this paper distributes information as
it is needed, and only once (probably) per boot of a machine."

This feature is really cool:
"This format allows the packet buffer to be reused if a reply is
generated; a reply has the same length as a request, and several
of the fields are the same."

Notes for parsers:
  "In theory, the length fields (ar$hln and ar$pln) are redundant,
  since the length of a protocol address should be determined by
  the hardware type (found in ar$hrd) and the protocol type (found
  in ar$pro).  It is included for optional consistency checking,
  and for network monitoring and debugging (see below)."

  "The opcode is to determine if this is a request (which may cause
  a reply) or a reply to a previous request.  16 bits for this is
  overkill, but a flag (field) is needed."

  "The sender hardware address and sender protocol address are
  absolutely necessary.  It is these fields that get put in a
  translation table."
*)

(*
TODO
- Timeout - for query REQUEST
- Aging - reverse it when receive packets from that host
- Retransmission count - for timed-out requests
- How often to "GC" on the table, to remove expired entries
- Deletion of entry upon detection of unreachability
- Implementing the 5527 protocol: probing to check if the address is available,
   etc.
- Allowed number of retransmitions, and min&max gaps between them.
*)


module type ARP_PARAMS = sig
  type network_device_id
  (*Initial size of the hashtable.*)
  val init_table_size : int
  (*Seconds before an ARP request is considered to have timed out.*)
  val request_timeout : float
  (*Seconds before an entry in the table is considered to have expired.*)
  val max_entry_age : float
  (*This identifies the network device, wrt to the network interface used --
    i.e., parameter N to Make below*)
  val device_id : network_device_id
end

let address_width_of = function
  | `Ethernet -> 6
  | `IPv4 -> 4

(*Raw ARP opcodes*)
(*FIXME classify them into more refined set of operations, based on RFC5527?*)
type arp_op =
  | Request (*i.e., ares_op$REQUEST in RFC826*)
  | Reply (*i.e., ares_op$REPLY in RFC826*)
;;

(*NOTE excludes Ethernet header info*)
type arp_packet_format = {
  (*FIXME use polymorphic variants instead of ints. Can then implement the
    checks in the algorithm more easily -- e.g., "?Do I have the hardware type
    in ar$hrd?"*)
  ar_hrd : [`Ethernet]; (*NOTE we only consider Ethernet here*)
  ar_pro : [`IPv4]; (*NOTE we only consider IPv4 here*)
  ar_hln : int; (*NOTE must be = 6, since we only consider Ethernet here*)
  ar_pln : int; (*NOTE must be = 4, since we only consider IPv4 here*)
  ar_op : arp_op;
  ar_sha : Macaddr.t;
  ar_spa : Ipaddr.V4.t;
  ar_tha : Macaddr.t;
  ar_tpa : Ipaddr.V4.t;
};;

type timestamp = float;;

module type TIME_SERVICE = sig
  (*Obtain the current time*)
  val time : unit -> timestamp
end

module type MONAD = sig
  type +'a m
  val return : 'a -> 'a m
  val (>>=) : 'a m -> ('a -> 'b m) -> 'b m
end

type entry_state =
  (*Address value, and the (local) timestamp the value was added.
    The timestamp can be used to purge the value, and/or request a refreshing,
    if the value is deemed to be too old.*)
  | Result of Macaddr.t * timestamp
  (*Indication that we don't have the info yet, but we also provide the time
    when we requested the info, to be used for timing out.*)
  | Waiting of timestamp
;;

type state =
  {
    (*NOTE to implement RFC826 properly, we cannot require the protocol to
      be IPv4 as done here*)
    protocol_addresses : Ipaddr.V4.t list;
    address_mapping : (Ipaddr.V4.t, entry_state) Hashtbl.t
  }
;;

(*Packet prefix is always the same: specialised for Ethernet and IPv4*)
let make_packet ~ar_op ~ar_sha ~ar_spa ~ar_tha ~ar_tpa : arp_packet_format =
  {
    ar_hrd = `Ethernet;
    ar_pro = `IPv4;
    ar_hln = address_width_of `Ethernet;
    ar_pln = address_width_of `IPv4;
    ar_op = ar_op;
    ar_sha = ar_sha;
    ar_spa = ar_tpa;
    ar_tha = ar_tha;
    ar_tpa = ar_tpa;
  }


module Make (N : V1.NETWORK with
              type macaddr = Macaddr.t)
         (Time_Service : TIME_SERVICE)
         (*Without the IO structure we cannot compute over 'a N.io.
           IO could be implemented using Lwt, Async, etc.*)
         (IO : MONAD with
           type 'a m = 'a N.io)
         (Params : ARP_PARAMS with
           type network_device_id = N.id) =
struct
  open IO

  let device_state : N.t m =
    (N.connect Params.device_id) >>= (fun state ->
    match state with
    | `Error error ->
      (
        match error with
        | `Unknown s -> failwith ("Unknown network error: " ^ s)
        | `Unimplemented ->
          failwith "Network error: Operation not yet implemented in the code"
        | `Disconnected ->
          failwith "Network error: The device has been previously disconnected"
      )
    | `Ok state -> return state)
  ;;

  let empty_state () : state =
    {
      protocol_addresses = [];
      address_mapping = Hashtbl.create ~random:false Params.init_table_size
    }
  ;;

  let addr_in_addrlist addr =
    (*NOTE this lookup could be done more efficiently, but we'd need access to
      the concrete representation of the addresses.*)
    List.exists (fun addr' -> Ipaddr.V4.compare addr addr' = 0)
  ;;

  let bind_ip_address (st : state) (ip_addr : Ipaddr.V4.t) =
    assert (not (addr_in_addrlist ip_addr st.protocol_addresses));
    { st with protocol_addresses = ip_addr :: st.protocol_addresses}
  ;;

  let unbind_ip_address (st : state) (ip_addr : Ipaddr.V4.t) =
    assert (addr_in_addrlist ip_addr st.protocol_addresses);
    { st with protocol_addresses =
                (*NOTE improvement: since addresses only appear at most once in
                  the list, we could stop the filter as soon as we hit the
                  address, and append the rest of the list.*)
                List.filter (fun ip_addr' ->
                  Ipaddr.V4.compare ip_addr ip_addr' <> 0)
                  st.protocol_addresses}
  ;;

  (*TODO i think need to use N.write, but need to define buffer type before
    that.*)
  let send (p : arp_packet_format) (*interface*) =
    failwith "TODO"
  ;;

  (*Performs the lookup on the table. It queries the network in these cases:
    - Table lacks an entry for the key we're looking for.
    - The table entry has aged too much.
    NOTE side-effect: might change the Hashtbl.t value in st.
  *)
  let lookup (st : state) (ip_addr : Ipaddr.V4.t) : Macaddr.t option m =
    device_state >>= (fun device_state ->
    let mac_address = N.mac device_state in
    if Hashtbl.mem st.address_mapping ip_addr then
      match Hashtbl.find st.address_mapping ip_addr with
      | Waiting ts ->
        (*If we've exceeded the request timeout then resend the request*)
        if ts < Time_Service.time () -. Params.request_timeout then
          begin
            (*NOTE here would increment retransmission count, and check if limit
              has been reached. This state info could be added to the "Waiting"
              record.*)
            make_packet
              ~ar_op:Request
              ~ar_sha:mac_address
              ~ar_spa:(failwith "IP?")(*FIXME which IP address to use?*)
              ~ar_tha:mac_address (*RFC826 says that this value doesn't
                                    matter in this setting.*)
              ~ar_tpa:ip_addr
            |> send;
            Waiting (Time_Service.time ())
            |> Hashtbl.replace st.address_mapping ip_addr;
          end;
        return None
      | Result (mac_addr, ts) ->
        if ts < Time_Service.time () -. Params.max_entry_age then
          begin
            (); (*FIXME resend request. Could also change the table, to remove the
                  entry. Shall we do this eagerly or lazily?*)
            return None
          end
        else
          (*NOTE we only guarantee freshness until "age" value.*)
          return (Some mac_addr)
    else
      (*FIXME here should make non-blocking call to request an ARP record from the
        network*)
      (*NOTE could cache request, so that if we later need to resend it we won't
        need to recreate it, but I don't think it would buy us much in this
        setting.*)
      return None)
  ;;

  (*Implements the algorithm described under "Packet Reception" in RFC826.
    NOTE side-effect: might change the Hashtbl.t value.*)
  let receive (st : state) (p : arp_packet_format) =
    device_state >>= (fun device_state ->
    let mac_address = N.mac device_state in
    (*NOTE these invariants were stated in comments earlier*)
    assert (p.ar_hrd = `Ethernet);
    assert (p.ar_pro = `IPv4);
    assert (p.ar_hln = address_width_of `Ethernet);
    assert (p.ar_pln = address_width_of `IPv4);
    let merge_flag =
      if Hashtbl.mem st.address_mapping p.ar_spa then
        begin
          Result (p.ar_sha, Time_Service.time ())
          |> Hashtbl.replace st.address_mapping p.ar_spa;
          true
        end
      else false in
    if addr_in_addrlist p.ar_tpa st.protocol_addresses then
      begin
        if not merge_flag then
          Result (p.ar_sha, Time_Service.time ())
          |> Hashtbl.add st.address_mapping p.ar_spa;

        if p.ar_op = Request then
          make_packet
            ~ar_op:Reply
            ~ar_sha:mac_address
            ~ar_spa:p.ar_tpa
            ~ar_tha:p.ar_sha
            ~ar_tpa:p.ar_spa
          |> send
      end;
    return ())
  ;;

  (*FIXME purge?*)
  (*Walks the cache, removing expired entries.*)
  let expire state = failwith "TODO";;

end;;


module Test_Arp =
  Make ((*FIXME get this from Mirage*))
    (struct
      let time = Unix.time
      end)
    (struct
      (*NOTE all these values are fudges*)
      let init_table_size = 0
      let request_timeout = 300.
      let max_entry_age = 300.
      let device_state = failwith "Some ID" (*FIXME*)
    end)
