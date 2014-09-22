(*NOTE I'm assuming a 64-bit precision for "int".*)
type ip_addr = int;; (*32 bits needed*)
type mac_addr = int;; (*48 bits needed*)

type state = (ip_addr, mac_addr) Hashtbl.t;;

(*Initial size of the hashtable*)
let kINIT_HT_SIZE = 0;;

let empty_state () : state = Hashtbl.create ~random:false kINIT_HT_SIZE;;

(*Adds an address pair to the cache.*)
let cache state (ip_addr, mac_addr) =
  let state' = Hashtbl.copy state in
  Hashtbl.add state' ip_addr mac_addr;
  state';;

(*Might need to query the network to perform the lookup. Returns future.*)
let lookup state ip_addr =
  if Hashtbl.mem state ip_addr then
    Some (Hashtbl.find state ip_addr)
  else
    (*FIXME here should make non-blocking call to request an ARP record from the
       network*)
    None;;

(*Walks the cache, removing expired entries.*)
let expire state = failwith "TODO";;

