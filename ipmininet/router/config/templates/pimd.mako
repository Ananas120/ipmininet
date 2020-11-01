hostname ${node.name}
password ${node.password}

% if node.pimd.logfile:
    log file ${node.pimd.logfile}
% endif

% for section in node.pimd.debug:
    debug pimd ${section}
% endfor
!
ip multicast-routing
!
% for itf in node.pimd.interfaces:
interface ${itf.name}
  % if itf.ssm:
   ip pim ssm
  % endif
  % if itf.igmp:
    ip igmp
  % endif
!
% endfor
