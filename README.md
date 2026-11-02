# Project 3: Subnetting and Forwarding

- Name: Adam Crayton
- Email: adamcrayton@u.boisestate.edu
- Class: CS525-001

## Design

Being that every address is a uint32_t in host byte order, so all of the subnet math is bit operations on the mask. cidr_mask() builds the mask whereas everything else derives from that. The network is addr & mask, the broadcast is addr | ~mask, and a block contains x when (x & mask) is equal to (addr & mask).

/0 (0xFFFFFFFF << (32 - prefix)) is a shift by 32 when the prefix is 0, and shifting a 32-bit value by its full width is undefined behavior in C. On x86 it usually gives back 0xFFFFFFF insead of 0, making the default route match only one address. cidr_mask() return 0 before it ever shifts.

/31 is a point-to-point link (RFC 3021), so both addresses are hosts and neither is a network or bradcoast address. cidr_first_host() returns the network address instead of network + 1, cidr_last_host() returns the broadcast address instead of braodcast - 1, and cidr_host_count() returns 2.

/32 is a single host, so it's network, broadcast, first host and last host all the same address and the host count is 1. /31 and /32 share the prefix >= 31 branch in the first and last host functions.

## Known Bugs or Issues

No bugs or issues are known in the project.


## Experience

Overall this project was alot of fun and was cool to see the output! Being able to see the routes and make this a fully implemented project was amazing to see. It was a little hard to start at first but with the help of some AI to get me started, it became a lot easier. I did have a lot more trouble getting full coverage on this in comparison to the other proejcts, but we got there. This was fun and can't wait for the next one!

