class web::firewall {
  # FIREWALL|WEB|section 10 - rules start from \d10 and up

  # ESTABLISHED rules
  shorewall::rule {
    "outbound established web http/https/rsync connections":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net',
      proto           => 'tcp',
      destinationport => '80,443,873',
      order           => 210;
    "inbound established web http/https/rsync connections":
      action          => 'ACCEPT',
      source          => 'net',
      destination     => 'fw',
      proto           => 'tcp',
      destinationport => '80,443,873',
      order           => 211;
  }

  # NEW rules
  shorewall::rule {
    "inbound http/https/rsync - host does not generally need to initiate these":
      action          => 'ACCEPT',
      source          => 'net',
      destination     => 'fw',
      proto           => 'tcp',
      destinationport => '80,443,873',
      order           => 410;
    "https is for redmine to sync git repos and gems, yum needs http for package downloads":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net',
      proto           => 'tcp',
      destinationport => '80,443',
      order           => 412;
    "RPM publishing requires rsync to koji specifically":
      action          => 'ACCEPT',
      source          => 'fw',
      destination     => 'net:23.21.173.22', # TODO, does a name work? can we get the IP from foreman?
      proto           => 'tcp',
      destinationport => '873',
      order           => 413;
  }
}
