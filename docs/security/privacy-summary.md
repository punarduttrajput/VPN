# Ferrum privacy summary

*Short, user-facing version of the [threat model](threat-model.md), suitable for
a product page. Every statement here is backed by a section of that document.*

## Your traffic is end-to-end encrypted

Everything between your devices is encrypted with WireGuard. Only the two
devices in a conversation hold the keys. Our coordination server, our relays and
your network provider can't read it.

## What the coordination server knows

To connect your devices, the coordination server keeps a directory of them:

- each device's **public** key, the name you gave it, and its tags;
- its mesh address;
- the network addresses it can be reached at, including addresses on your local
  network, so your devices can find each other directly;
- which sign-in identity owns which device.

It **does not** see your traffic, your DNS queries, or which of your devices
actually talk to each other. A device stays in the directory until an
administrator removes it. Its network addresses are overwritten whenever they
change, so no location history is kept. Server logs and metrics record counts
and events, never your keys, addresses or identity.

## What a relay knows

When two devices can't reach each other directly, a relay passes their
already-encrypted packets along. A relay sees which device keys exchange
packets, the devices' public network addresses, and how much traffic flows and
when. It **can't** read the packets. Our relays don't log these details, and
direct connections take over as soon as one can be made.

## What your network can see

Your Wi-Fi or internet provider can see that you're connected to Ferrum
endpoints, and how much and when. It can't see the contents. With the QUIC or
MASQUE transports, your traffic looks like ordinary web traffic. The connection
is pinned to the right server's key (automatically between your devices, and
when configured for a proxy), so it can't be quietly intercepted.

## DNS

While you're connected, your DNS queries go through the encrypted tunnel to the
mesh's resolver, and plaintext DNS is blocked from leaking onto your local
network. Browsers that use their own encrypted DNS (DoH) bypass this, so
configure them to use the system resolver if that matters to you.

## What Ferrum is not

Ferrum is a private network for your devices. It is not an anonymity service:
whoever runs the coordination server and relays is trusted to run them honestly,
and devices you connect to can see your public address. For the full details,
including failure modes and known limitations, read the
[threat model](threat-model.md).
