(*
We want to have a language-assisted distinction between persistent and transient
values. Persistent values are storage backed. Transient values are entirely
calculated from persistent values. We don't need to remember transient values
(but doing so improves performance); we need to remember which persistent values
they were computed from.

Some ideas:
- something transient can never become persistent (or contribute to the creation
of persistent objects).
- persistent objects can contribute to the creation of persistent or transient
objects.

So we'd like a language-assisted way of keeping track of which persistent
objects were used to create a transient object, and to replay this computation
at will to recreate the transient object (assuming that the persistent objects
are available).

This file contains a sketch of an idea to do this. We specify computations in
terms of fine-grained "snapshots" of the application of functions. The functions
themselves are pure, and the computations ultimately rely on values that should
be persistent (though this is not enforced in this model). Then we can replay
the computation.

Ideally we might want to keep track of intermediate stages of the computation
(this should form a finite polymorphic list).
*)

(*A transient value tracks the function, its original arguments, and its result*)
type ('f, 'a, 'r) transient =
  | Id : 'a -> ('a -> 'a, 'a, 'a) transient
  | Apply : (('a -> 'b) * ('c -> 'a, 'c, 'a) transient) -> ('c -> 'b, 'c, 'b) transient
  | Apply2 : (('a -> 'b -> 'c) * ('d -> 'a, 'd, 'a) transient * ('e -> 'b, 'e, 'b) transient) -> ('d * 'e -> 'c, 'd * 'e, 'c) transient
;;

(*Compute the actual value of a transient value.*)
(*NOTE we can play tricks to "serialise" this, as shown later.*)
let rec recompute : type f a r. (f, a, r) transient -> r = function
  | Id x -> x
  | Apply (f, t) -> f (recompute t)
  | Apply2 (f, t1, t2) -> f (recompute t1) (recompute t2)
;;

let example = Apply ((fun x -> x + 1), Id 4);;
recompute example;;

(*NOTE This following is bad form, since the closure has free variable x*)
let plus x y = Apply ((fun z -> x + z), Id y);;

recompute (plus 3 4);;

(*Better form, but a bit awkward*)
let plus x y = Apply ((fun (x, y) -> x + y), Id (x, y));;

recompute (plus 3 4);;

(*Composing the results of computations feels awkward if done like this*)
recompute
  (plus
     5
     (recompute (plus 3 4)));;

let uncurry f (x, y) = f x y;;

let (++) = uncurry (+);;

(*Hmm useless*)
let plus' x y z =
   let xy = Apply ((++), Id (x, y))
   in recompute xy
;;

(*Now have added the Apply2 combinator. Things look less awkward.*)
let plus' x y z =
   let xy = Apply ((++), Id (x, y))
   in Apply2 ((+), Id z, xy)
;;

(*Can rewrite plus' as follows*)
let plus' x y z =
   let xy = Apply2 ((+), Id x, Id y)
   in Apply2 ((+), Id z, xy)
;;

plus' 4 5 6
|> recompute;;

(*
So far, so good.
Now let's tweak functions a bit to carry names as well as functions.
This will provide us with a weak form of serialisation.
*)

(*Instead of building transient values using functions, we will build them out
  such records. Note that the earlier definitions don't need to be changed.*)
type 'a valerie = { v : 'a; name : string };;

(*We now define the + and integer versions of these records.*)
let add = { v = (+); name = "add" };;
let value i = { v = i; name = string_of_int i};;

(*Our new plus function -- which accepts selectors to indicate whether we're
  actual value, or the "serialisation"*)
let plus s_f s_v x y z =
   let xy = Apply2 (s_f add, Id (s_v x), Id (s_v y))
   in Apply2 (s_f add, Id (s_v z), xy)
;;

(*We can specialise the above function, using the selectors.*)
let plus_fun = plus (fun r -> r.v) (fun r -> r.v);;
let plus_label = plus (fun r x y -> r.name ^ "(" ^ x ^ ", " ^ y ^ ")") (fun r -> r.name);;


(*And now we can see the results*)

plus_fun (value 4) (value 5) (value 6)
|> recompute;;

plus_label (value 4) (value 5) (value 6)
|> recompute;;

