(*
   We want to represent a partial function:
   IP_addr -> MAC_addr
   But the evaluation of this function is weird: we don't have all of its
   evaluatio at the same time. Moreover, its value can vary over time, as hosts
   join and leave the network.

   Ideas:
   - If we cannot complete the evaluation, then just return None and have the
   client try again in the future. In the mean time, we will try and obtain a
   value from the network. This is the behaviour suggested by RFC826, under
   "Packet Generation".
   - If we cannot complete the evaluation, then return immediately to the client
   with a subscription to a waiting list that will be advised as soon as we have
   a value (or will timeout).
   - Block until we can complete the evaluation (or time out).

   In each case, what's persistent, and what's transient?
   - Persistent: current config of the database: mappings from IPs to MACs.
       Also include waiting lists?
       Also, what needs to be done in case db is reloaded?
        This reduces to figuring out what to do in case a MAC address for an IP
          address is updated. Do we go back in time and tell every past caller?
          Or do we rely on them to recheck?
          This is not really needed, since we expire values based on age.
          So in the worst case, we could start with an empty database.
   - Transient: timeouts of lookups, ages of values, and associated state.

  How is all this different from the state info that's kept at other layers in
   the network stack? To be determined...
*)

(*NOTE this implementation is specialised for Ethernet and IP,
  i.e., using the language of RFC826 I'm assuming that
  ar$pro={ether_type$DOD_INTERNET} and ar$hrd={ares_hrd$Ethernet}.
  Consequently, it should always be the case that ar$hln=6 (bytes) and ar$pln=4.
*)

(*NOTE I'm assuming that ethernet packet has been parsed according to
  "Packet format" section of RFC826. For ARP code to be run, the Protocol Type
  field of the Ethernet packet header must be ether_type$ADDRESS_RESOLUTION.
*)

(*
  NOTE (needs to be refined)
   Assumes source-related info is correct.
   Ignores target-related info, even if arest_op$REPLY.
*)

(* From RFC826:
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
- Deletion of entry upon detection of unreachability
- Implementing the 5527 protocol: probing to check if the address is available,
   etc.
- Allowed number of retransmitions, and min&max gaps between them.
*)

(*Raw ARP opcodes*)
(*FIXME classify them into more refined set of operations, based on RFC5527?*)
type arp_op =
  | Request (*i.e., ares_op$REQUEST in RFC826*)
  | Reply (*i.e., ares_op$REPLY in RFC826*)

(*NOTE excludes Ethernet header info*)
type arp_packet_format = {
  (*FIXME use polymorphic variants instead of ints. Can then implement the
    checks in the algorithm more easily -- e.g., "?Do I have the hardware type
    in ar$hrd?"*)
  ar_hrd : int; (*NOTE must be = 1*)
  ar_pro : int; (*NOTE must be = 6*)
  ar_hln : int; (*NOTE must be = 6*)
  ar_pln : int; (*NOTE must be = 4*)
  ar_op : arp_op;
  ar_sha : Macaddr.t;
  ar_spa : Ipaddr.V4.t;
  ar_tha : Macaddr.t;
  ar_tpa : Ipaddr.V4.t;
}

type timestamp = float (*FIXME or use Int64.t?*)

type entry_state =
  (*Address value, and the (local) timestamp the value was added.
    The timestamp can be used to purge the value, and/or request a refreshing,
    if the value is deemed to be too old.*)
  | Result of Macaddr.t * timestamp
  (*Indication that we don't have the info yet, but we also provide the time
    when we requested the info, to be used for timing out.*)
  | Waiting of timestamp

type state = (Ipaddr.V4.t, entry_state) Hashtbl.t;;

(*Initial size of the hashtable*)
let kINIT_HT_SIZE = 0(*FIXME fudge*);;

let empty_state () : state = Hashtbl.create ~random:false kINIT_HT_SIZE;;

(*Adds an address pair to the cache. If mapping already exists for ip_addr then
  it is removed.*)
let cache (st : state) ((ip_addr : Ipaddr.V4.t), (mac_addr : Macaddr.t)) =
  (*NOTE deliberate shadowing, to avoid manipulating the original st value.
    Hashtbl isn't pure*)
  let st = Hashtbl.copy st in (*NOTE duplication to avoid manipulating original st*)
  if Hashtbl.mem st ip_addr then
    Hashtbl.remove st ip_addr;
  Hashtbl.add st ip_addr (Result (mac_addr, Unix.time ()));
  st
;;

(*Might need to query the network to perform the lookup. Returns future.*)
let lookup state ip_addr =
  if Hashtbl.mem state ip_addr then
    Some (Hashtbl.find state ip_addr)
  else
    (*FIXME here should make non-blocking call to request an ARP record from the
       network*)
    None
;;

(*FIXME need network interface*)
let send (p : arp_packet_format) (*interface*) =
  failwith "TODO"
;;
let my_ip_address : Ipaddr.V4.t = Ipaddr.V4.make 192 168 1 2;; (*FIXME*)
let my_mac_address : Macaddr.t = Macaddr.of_string_exn "0f:ff:ff:ff:ff:ff";; (*FIXME*)

(*Implements the algorithm described under "Packet Reception" in RFC826*)
let receive (st : state) (p : arp_packet_format) =
  (*NOTE these invariants were stated in comments earlier*)
  assert (p.ar_hrd = 1);
  assert (p.ar_pro = 6);
  assert (p.ar_hln = 6);
  assert (p.ar_pln = 4);
  let merge_flag =
    if Hashtbl.mem st p.ar_spa then
      begin
        Result (p.ar_sha, Unix.time ())
        |> Hashtbl.replace st p.ar_spa;
        true
      end
    else false in
  if p.ar_tpa = my_ip_address then
    begin
      if not merge_flag then
        Result (p.ar_sha, Unix.time ())
        |> Hashtbl.add st p.ar_spa;

      if p.ar_op = Request then
        {
          ar_hrd = 1;
          ar_pro = 6;
          ar_hln = 6;
          ar_pln = 4;
          ar_op = Reply;
          ar_sha = my_mac_address;
          ar_spa = my_ip_address;
          ar_tha = p.ar_sha;
          ar_tpa = p.ar_spa;
        }
        |> send
    end
;;

(*FIXME purge?*)
(*Walks the cache, removing expired entries.*)
let expire state = failwith "TODO";;

