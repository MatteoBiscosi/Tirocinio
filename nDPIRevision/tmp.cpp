



    if (flow_to_process->ndpi_flow->num_extra_packets_checked <
        flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
        /*
         * Your business logic starts here.
         *
         * This example does print some information about
         * TLS client and server hellos if available.
         *
         * You could also use nDPI's built-in json serialization
         * and send it to a high-level application for further processing.
         *
         * EoE - End of Example
         */

        if (flow_to_process->detected_l7_protocol.master_protocol == NDPI_PROTOCOL_TLS ||
            flow_to_process->detected_l7_protocol.app_protocol == NDPI_PROTOCOL_TLS)
        {
            if (flow_to_process->tls_client_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.hello_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                printf("[%8llu, %d, %4d][TLS-CLIENT-HELLO] version: %s | sni: %s | alpn: %s\n",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       flow_to_process->flow_id,
                       ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                            &unknown_tls_version),
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.client_requested_server_name,
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn : "-"));
                flow_to_process->tls_client_hello_seen = 1;
            }
            if (flow_to_process->tls_server_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.certificate_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                printf("[%8llu, %d, %4d][TLS-SERVER-HELLO] version: %s | common-name(s): %.*s | "
                       "issuer: %s | subject: %s\n",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       flow_to_process->flow_id,
                       ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                            &unknown_tls_version),
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names_len,
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names,
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN : "-"),
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN : "-"));
                flow_to_process->tls_server_hello_seen = 1;
            }
        }
    }
}
