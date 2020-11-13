<% zone = node.named.zones[node.current_filename] %>
%if zone.soa_record:
$TTL ${zone.soa_record.ttl}
@	IN	SOA	${zone.soa_record.rdata}
%endif

%for record in zone.records:
${record.domain_name}   ${record.ttl}	IN	${record.rtype}	${record.rdata}
%endfor
