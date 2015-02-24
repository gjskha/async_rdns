async_rdns
==========

Look up rDNS asynchronously. 

*Usage*

    $ async_rdns -i [interval] -m [ # of concurrent queries to run] [x.x.x.x y.y.y.y | x.x.x.x/yy]

e.g.,

    $ async_rdns -i 64 24.24.24.0/23
    
    24.24.24.0	cpe-24-24-24-0.twcny.res.rr.com
    24.24.24.64	cpe-24-24-24-64.twcny.res.rr.com
    24.24.24.128	cpe-24-24-24-128.twcny.res.rr.com
    24.24.24.192	cpe-24-24-24-192.twcny.res.rr.com
    24.24.25.0	NXDOMAIN
    24.24.25.64	cpe-24-24-25-64.twcny.res.rr.com
    24.24.25.128	cpe-24-24-25-128.twcny.res.rr.com
    24.24.25.192	cpe-24-24-25-192.twcny.res.rr.com
    $
    
and so on.

*Dependencies*

You might have to install the UDNS development libraries first, available as a package via yum and apt-get at least.

