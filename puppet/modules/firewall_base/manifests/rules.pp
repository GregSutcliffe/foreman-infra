class firewall_base::rules {
  # FIREWALL|BASE|section 00 - rules start from \d00 and up

  shorewall::rule_section {
    # Shorewalll demands these stay in this order
    'ALL':         order => 100;
    'ESTABLISHED': order => 200;
    'RELATED':     order => 300;
    'NEW':         order => 400;
  }

  # basic DNS/NTP rules, can go in ALL
  shorewall::rule {
    "outbound-dns":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net',
      proto           => 'udp,tcp',
      destinationport => '53',
      order           => 101;
    "outbound-ntp":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net',
      proto           => 'udp',
      destinationport => '123',
      order           => 102;
  }

  # ESTABLISHED ssh rules
  shorewall::rule {
    "outbound established ssh":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net',
      proto           => 'tcp',
      destinationport => '22',
      order           => 201;
    "inbound established ssh":
      action          => 'ACCEPT',
      source          => 'net',
      destination     => 'fw',
      proto           => 'tcp',
      destinationport => '22',
      order           => 202;
  }

  # NEW ssh/puppet rules
  shorewall::rule {
    "inbound ssh only, host should not be SSH'ing out":
      action          => 'ACCEPT',
      source          => 'net',
      destination     => 'fw',
      proto           => 'tcp',
      destinationport => '22',
      order           => 401;
    "puppet needs to be able to reach the puppetmaster":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net:208.74.145.200', # TODO, does a name work? can we get the IP from foreman?
      proto           => 'tcp',
      destinationport => '8140',
      order           => 402;
  }

}
