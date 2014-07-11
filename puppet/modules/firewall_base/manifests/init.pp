class firewall_base (
  $logging = 'DEBUG'
) {

  # Shorewall is in EPEL
  case $::operatingsystem {
    centos: { class { 'epel': before => Class['shorewall'] } }
  }

  class { 'shorewall': }

  # Set this to yes regardless or you can't even stop the firewall
  augeas { 'enable_shorewall_startup':
    changes => "set /files/etc/shorewall/shorewall.conf/STARTUP_ENABLED Yes",
    lens    => 'Shellvars.lns',
    incl    => '/etc/shorewall/shorewall.conf',
    notify  => Service[shorewall];
  }

  # If you want logging:
  shorewall::params {
    'LOG':  value => $logging;
  }

  shorewall::zone { 'net':
    type => 'ipv4';
  }

  shorewall::interface { 'eth0':
    zone    => 'net',
    rfc1918 => true,
    options => 'tcpflags,routefilter,nosmurfs,logmartians';
  }

  shorewall::policy {
    'fw-to-fw - host-internal is ok':
      sourcezone      => 'fw',
      destinationzone => 'fw',
      policy          => 'ACCEPT',
      order           => 100;
    'fw-to-net - default DROP to prevent phone-home compromises':
      sourcezone      => 'fw',
      destinationzone => 'net',
      policy          => 'DROP',
      shloglevel      => '$LOG',
      order           => 110;
    'net-to-fw':
      sourcezone      => 'net',
      destinationzone => 'fw',
      policy          => 'DROP',
      shloglevel      => '$LOG',
      order           => 120;
  }

  include firewall_base::rules
}
