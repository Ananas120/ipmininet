<%
    # Read value from node or use default value
    def getConfig(key, default):
        if key in node['openr']:
            val = node['openr'][key]
        else:
            val = default
        return "--{k}={v}".format(k=key, v=val)
%>\
${getConfig("alloc_prefix_len", 128)} \
${getConfig("assume_drained", False)} \
${getConfig("config_store_filepath", "/tmp/aq_persistent_config_store.bin")} \
${getConfig("decision_debounce_max_ms", 250)} \
${getConfig("decision_debounce_min_ms", 10)} \
${getConfig("decision_rep_port", 60004)} \
${getConfig("domain","openr")} \
${getConfig("dryrun", False)} \
${getConfig("enable_subnet_validation", True)} \
${getConfig("enable_fib_sync", False)} \
${getConfig("enable_health_checker", False)} \
${getConfig("enable_legacy_flooding", True)} \
${getConfig("enable_lfa", False)} \
${getConfig("enable_netlink_fib_handler", True)} \
${getConfig("enable_netlink_system_handler", True)} \
${getConfig("enable_perf_measurement", True)} \
${getConfig("enable_prefix_alloc", False)} \
${getConfig("enable_rtt_metric", True)} \
${getConfig("enable_secure_thrift_server", False)} \
${getConfig("enable_segment_routing", False)} \
${getConfig("enable_spark", True)} \
${getConfig("enable_v4", False)} \
${getConfig("enable_watchdog", True)} \
${getConfig("fib_handler_port", 60100)} \
${getConfig("fib_rep_port", 60009)} \
${getConfig("health_checker_ping_interval_s", 3)} \
${getConfig("health_checker_rep_port", 60012)} \
${getConfig("ifname_prefix", "")} \
${getConfig("iface_regex_exclude", "")} \
${getConfig("iface_regex_include", "")} \
${getConfig("ip_tos", 192)} \
${getConfig("key_prefix_filters", "")} \
${getConfig("kvstore_flood_msg_per_sec", 0)} \
${getConfig("kvstore_flood_msg_burst_size", 0)} \
${getConfig("kvstore_flood_msg_per_sec", 0)} \
${getConfig("kvstore_ttl_decrement_ms", 1)} \
${getConfig("kvstore_zmq_hwm", 65536)} \
${getConfig("link_flap_initial_backoff_ms", 1000)} \
${getConfig("link_flap_max_backoff_ms", 60000)} \
${getConfig("link_monitor_cmd_port", 60006)} \
${getConfig("loopback_iface", "lo")} \
${getConfig("memory_limit_mb", 300)} \
${getConfig("minloglevel", 0)} \
${getConfig("node_name", "")} \
${getConfig("override_loopback_addr", False)} \
${getConfig("prefix_manager_cmd_port", 60011)} \
${getConfig("prefixes", "")} \
${getConfig("redistribute_ifaces", "lo1")} \
${getConfig("seed_prefix", "")} \
${getConfig("set_leaf_node", False)} \
${getConfig("set_loopback_address", False)} \
${getConfig("spark_fastinit_keepalive_time_ms", 100)} \
${getConfig("spark_hold_time_s", 30)} \
${getConfig("spark_keepalive_time_s", 3)} \
${getConfig("static_prefix_alloc", False)} \
${getConfig("tls_acceptable_peers", "")} \
${getConfig("tls_ecc_curve_name", "prime256v1")} \
${getConfig("tls_ticket_seed_path", "")} \
${getConfig("x509_ca_path", "")} \
${getConfig("x509_cert_path", "")} \
${getConfig("x509_key_path", "")} \
${getConfig("logbufsecs", 0)} \
${getConfig("log_dir", "/var/log")} \
${getConfig("max_log_size", 1)} \
${getConfig("v", 1)} \
