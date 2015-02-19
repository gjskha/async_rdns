async_rdns
==========

Look up rDNS asynchronously. 

*Usage*

    $ async_rdns -i [interval] -m [ number of queries to run] -e [exception] [x.x.x.x y.y.y.y | x.x.x.x/yy]

e.g.,

    $ async_rdns -i 64 24.24.24.0/23
    
*Dependencies*

You might have to install the UDNS development libraries first, available as a package via yum and apt-get at least.

