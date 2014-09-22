(* Impure ARP cache *)

type ip_addr = int
type mac_addr = int

type state

val import : state -> ()
val export : () -> state

(*FIXME use standard names for these functions, from standard APIs*)

(*Adds an address pair to the cache.*)
val cache : ip_addr * mac_addr -> ()

(*Might need to query the network to perform the lookup. Returns future.*)
val lookup : ip_addr -> (() -> mac_addr option)

(*Walks the cache, removing expired entries*)
val expire : () -> ()

