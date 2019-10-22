do
    -- gm
    local p_gm = Proto('gmv1.1', 'XDJA GMv1.1')

    local r_content_type = {
        [20] = "ChangeCipherSpec",
        [21] = "Alert",
        [22] = 'Handshake',
        [23] = 'ApplicationData',
        [80] = 'Site2site',
    }
    p_gm.fields.record = ProtoField.bytes("tls.record.xdja", "Record Layer", base.NONE)
    p_gm.fields.r_type = ProtoField.uint8('tls.record.xdja.type', 'Content Type', base.DEC, r_content_type)
    p_gm.fields.r_version = ProtoField.uint16('tls.record.xdja.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_gm.fields.r_len = ProtoField.uint16("tls.record.xdja.length", "Length", base.DEC)
    -- hanshake
    local hs_type = {
        [1]  = "ClientHello",
        [2]  = "ServerHello",
        [11] = "Certificate",
        [12] = "ServerKeyExchange",
        [13] = "CertificateRequest",
        [14] = "ServerHelloDone",
        [15] = "CertificateVerify",
        [16] = "ClientKeyExchange",
        [20] = "Finished",
    }
    p_gm.fields.hs = ProtoField.bytes("tls.record.xdja.content", "Handshake", base.NONE)
    p_gm.fields.hs_type = ProtoField.uint8("tls.handshake.xdja.type", "Handshake Type", base.DEC, hs_type)
    p_gm.fields.hs_len  = ProtoField.uint24("tls.handshake.xdja.length", "Length", base.DEC)
    p_gm.fields.hs_version  = ProtoField.uint16('tls.handshake.xdja.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_gm.fields.hs_random = ProtoField.bytes('tls.handshake.xdja.random', 'Random', base.NONE)
    p_gm.fields.hs_gmt_time = ProtoField.absolute_time('tls.handshake.xdja.gmt_time', 'GMT Unix Time', base.LOCAL)
    p_gm.fields.hs_random_bytes = ProtoField.bytes('tls.handshake.xdja.random_bytes', 'Random Bytes', base.NONE)
    p_gm.fields.hs_sess_id_len = ProtoField.uint8('tls.handshake.xdja.session_id_len', 'Session ID Length', base.DEC)
    p_gm.fields.hs_sess_id = ProtoField.bytes('tls.handshake.xdja.session_id', 'Session ID', base.NONE)
    p_gm.fields.hs_cipher_suites_len = ProtoField.uint16('tls.handshake.xdja.cipher_suites_len', 'Cipher Suites Length', base.DEC)
    p_gm.fields.hs_cipher_suites = ProtoField.bytes('tls.handshake.xdja.cipher_suites', 'Cipher Suites', base.NONE)
    local ciphers = {
        [0x0000] = "TLS_NULL_WITH_NULL_NULL ",
        [0x0001] = "TLS_RSA_WITH_NULL_MD5",
        [0x0002] = "TLS_RSA_WITH_NULL_SHA",
        [0x0003] = "TLS_SM2_WITH_NULL_NULL",
        [0x003B] = "TLS_RSA_WITH_NULL_SHA256",
        [0x0004] = "TLS_RSA_WITH_RC4_128_MD5",
        [0x0005] = "TLS_RSA_WITH_RC4_128_SHA",
        [0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_S",
        [0x002F] = "TLS_RSA_WITH_AES_128_CBC_SH",
        [0x0035] = "TLS_RSA_WITH_AES_256_CBC_SH",
        [0x003C] = "TLS_RSA_WITH_AES_128_CBC_SH",
        [0x003D] = "TLS_RSA_WITH_AES_256_CBC_SH",
        [0x1301] = "TLS_AES_128_GCM_SHA256",
        [0x1302] = "TLS_AES_256_GCM_SHA384",
        [0x1303] = "TLS_CHACHA20_POLY1305_SHA25",
        [0x1304] = "TLS_AES_128_CCM_SHA256",
        [0x1305] = "TLS_AES_128_CCM_8_SHA256",
        [0xE001] = "GM_ECDHE_SM1_SM3",
        [0xE003] = "GM_ECC_SM1_SM3",
        [0xE005] = "GM_IBSDH_SM1_SM3",
        [0xE007] = "GM_IBC_SM1_SM3",
        [0xE009] = "GM_RSA_SM1_SM3",
        [0xE00A] = "GM_RSA_SM1_SHA1",
        [0xE011] = "GM_ECDHE_SM4_SM3",
        [0xE013] = "GM_ECC_SM4_SM3",
        [0xE015] = "GM_IBSDH_SM4_SM3",
        [0xE017] = "GM_IBC_SM4_SM3",
        [0xE019] = "GM_RSA_SM4_SM3",
        [0xE01A] = "GM_RSA_SM4_SHA1",
        [0xE00A] = "TLS_RSA_WITH_SM1_CBC_SHA",
        [0xE00B] = "TLS_RSA_WITH_SM1_ECB_SHA",
        [0xFF0C] = "TLS_RSA_WITH_SM4_CBC_SHA",
        [0xFF0D] = "TLS_RSA_WITH_SM4_ECB_SHA",
        [0xFF1A] = "TLS_SM2_WITH_SM1_CBC_SM3",
        [0xFF1B] = "TLS_SM2_WITH_SM1_ECB_SM3",
        [0xFF1C] = "TLS_SM2_WITH_SM4_CBC_SM3",
        [0xFF1D] = "TLS_SM2_WITH_SM4_ECB_SM3",
        [0xFF20] = "TLS_SM2_WITH_SM4_ECB_CRC32C",
        [0xFF31] = "TLS_SM4_GCM_SM3",
    }
    p_gm.fields.hs_cipher_suite = ProtoField.uint16('tls.handshake.xdja.cipher_suite', 'Cipher Suite', base.HEX, ciphers)
    p_gm.fields.hs_compress_methods_len = ProtoField.uint8('tls.handshake.xdja.compress_methods_len', 'Compress Methods Len', base.DEC)
    p_gm.fields.hs_compress_methods = ProtoField.bytes('tls.handshake.xdja.compress', 'Compress Methods', base.NONE)
    local compress = {
        [0] = "null",
    }
    p_gm.fields.hs_compress_method = ProtoField.uint8('tls.handshake.xdja.compress_method', 'Compress Method', base.HEX, compress)

    p_gm.fields.hs_certificates_len = ProtoField.uint24('tls.handshake.xdja.certificates_len', 'Certificates Length', base.DEC)
    p_gm.fields.hs_certificates = ProtoField.bytes('tls.handshake.xdja.certificates', 'Certificates', base.NONE)
    p_gm.fields.hs_certificate_len = ProtoField.uint24('tls.handshake.xdja.certificate_len', 'Certificate Length', base.DEC)
    p_gm.fields.hs_certificate = ProtoField.bytes('tls.handshake.xdja.certificate', 'Certificate', base.NONE)

    p_gm.fields.hs_ske_sign = ProtoField.bytes('tls.handshake.xdja.ske_signature', 'ServerKeyExchange Signature', base.NONE)

    p_gm.fields.hs_cert_types_len = ProtoField.uint8('tls.handshake.xdja.cert_types_len', 'Certificate Types Length', base.DEC)
    p_gm.fields.hs_cert_types = ProtoField.bytes('tls.handshake.xdja.cert_types', 'Certificate Types', base.NONE)

    local cert_types = {
        [1] = "rsa_sign",
        [2] = "dss_sign",
        [3] = "rsa_fixed_dh",
        [4] = "dss_fixed_dh",
        [5] = "rsa_ephemeral_dh_RESERVED",
        [6] = "dss_ephemeral_dh_RESERVED",
        [20] = "fortezza_dms_RESERVED",
        [50] = "sm2_legacy",
        [80] = "sm2",
    }
    p_gm.fields.hs_cert_type = ProtoField.uint8('tls.handshake.xdja.cert_type', 'Certificate Type', base.DEC, cert_types)
    p_gm.fields.hs_DNs_len = ProtoField.uint16('tls.handshake.xdja.distinguished_names_len', 'Distinguished Names Length', base.DEC)
    p_gm.fields.hs_DNs = ProtoField.bytes('tls.handshake.xdja.distinguished_names', 'Distinguished Names', base.NONE)
    p_gm.fields.hs_DN_len = ProtoField.uint16('tls.handshake.xdja.distinguished_name_len', 'Distinguished Name Length', base.DEC)
    p_gm.fields.hs_DN = ProtoField.string('tls.handshake.xdja.distinguished_name', 'Distinguished Name', base.NONE)

    p_gm.fields.hs_cv_sign_len = ProtoField.uint16('tls.handshake.xdja.cv_signature', 'CertificateVerify Signature', base.DEC)
    p_gm.fields.hs_cv_sign = ProtoField.bytes('tls.handshake.xdja.cv_signature', 'CertificateVerify Signature', base.NONE)

    p_gm.fields.alert = ProtoField.bytes('tls.handshake.xdja.alert', 'Alert', base.NONE)
    local alert_levels = {
        [1] = "warning",
        [2] = "fatal",
    }
    p_gm.fields.alert_level = ProtoField.uint8('tls.handshake.xdja.alert_level', 'Alert Level', base.DEC, alert_levels)
    local alert_desc = {
        [0] = "close_notify",
        [10] = "unexpected_message",
        [20] = "bad_record_mac",
        [21] = "decryption_failed_RESERVED",
        [22] = "record_overflow",
        [30] = "decompression_failure",
        [40] = "handshake_failure",
        [41] = "no_certificate_RESERVED",
        [42] = "bad_certificate",
        [43] = "unsupported_certificate",
        [44] = "certificate_revoked",
        [45] = "certificate_expired",
        [46] = "certificate_unknown",
        [47] = "illegal_parameter",
        [48] = "unknown_ca",
        [49] = "access_denied",
        [50] = "decode_error",
        [51] = "decrypt_error",
        [60] = "export_restriction_RESERVED",
        [70] = "protocol_version",
        [71] = "insufficient_security",
        [80] = "internal_error",
        [90] = "user_canceled",
        [100] = "no_renegotiation",
        [110] = "unsupported_extension",
    }
    p_gm.fields.alert_desc = ProtoField.uint8('tls.handshake.xdja.alert_desc', 'Alert Description', base.DEC, alert_desc)

    local function hs_handler_hr(tvb, pinfo, tree)
    end
    local function hs_handler_ch(tvb, pinfo, tree)
        pinfo.cols.info = "ClientHello"
        local offset = 0

        local v_version = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_version, v_version)

        local v_random = tvb(offset, 32)
        local t = tree:add(p_gm.fields.hs_random, v_random)
        local v_gmt_time = tvb(offset, 4)
        offset = offset + 4
        t:add(p_gm.fields.hs_gmt_time, v_gmt_time)
        local v_real_random = tvb(offset, 28)
        offset = offset + 28
        t:add(p_gm.fields.hs_random_bytes, v_real_random)

        local v_sess_id_len = tvb(offset, 1)
        offset = offset + 1
        tree:add(p_gm.fields.hs_sess_id_len, v_sess_id_len)

        local v_sess_id = tvb(offset, v_sess_id_len:uint())
        offset = offset + v_sess_id_len:uint()
        tree:add(p_gm.fields.hs_sess_id, v_sess_id)

        local v_cihper_suites_len = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_cipher_suites_len, v_cihper_suites_len)

        local cipher_suites_len = v_cihper_suites_len:uint() or 0
        if (cipher_suites_len ~= 0) then
            local v_cipher_suites  = tvb(offset, cipher_suites_len)
            local sub_cipher_suites = tree:add(p_gm.fields.hs_cipher_suites, v_cipher_suites)

            sub_cipher_suites:set_text("Cipher Suites ("..(cipher_suites_len / 2).." suites)")
            for i = 1, cipher_suites_len / 2, 1 do
                local v_cipher_suite = tvb(offset, 2)
                offset = offset + 2
                sub_cipher_suites:add(p_gm.fields.hs_cipher_suite, v_cipher_suite)
                end
            end

        local v_compress_methods_len = tvb(offset, 1)
        offset = offset + 1
        tree:add(p_gm.fields.hs_compress_methods_len, v_compress_methods_len)

        local compress_methods_len = v_compress_methods_len:uint() or 0
        if (v_compress_methods_len ~= 0) then
            local v_compress_methods = tvb(offset, compress_methods_len)
            local sub_compress_methods = tree:add(p_gm.fields.hs_compress_methods, v_compress_methods)

            sub_compress_methods:set_text("Compress Methods ("..(compress_methods_len).." method)")
            for i = 1, compress_methods_len, 1 do
                local v_compress_method = tvb(offset, 1)
                offset = offset + 1
                sub_compress_methods:add(p_gm.fields.hs_compress_method, v_compress_method)
            end
        end

    end
    local function hs_handler_sh(tvb, pinfo, tree)
        pinfo.cols.info = "ServerHello"

        local offset = 0
        local v_version = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_version, v_version)

        local v_random = tvb(offset, 32)
        local t = tree:add(p_gm.fields.hs_random, v_random)
        local v_gmt_time = tvb(offset, 4)
        offset = offset + 4
        t:add(p_gm.fields.hs_gmt_time, v_gmt_time)
        local v_real_random = tvb(offset, 28)
        offset = offset + 28
        t:add(p_gm.fields.hs_random_bytes, v_real_random)

        local v_sess_id_len = tvb(offset, 1)
        offset = offset + 1
        tree:add(p_gm.fields.hs_sess_id_len, v_sess_id_len)

        local v_sess_id = tvb(offset, v_sess_id_len:uint())
        offset = offset + v_sess_id_len:uint()
        tree:add(p_gm.fields.hs_sess_id, v_sess_id)

        local v_cipher_suite = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_cipher_suite, v_cipher_suite)

        local v_compress_method = tvb(offset, 1)
        offset = offset + 1
        tree:add(p_gm.fields.hs_compress_method, v_compress_method)
    end
    local function hs_handler_ct(tvb, pinfo, tree)
        pinfo.cols.info = "Certificate"
        local offset = 0

        local v_certificates_len = tvb(offset, 3)
        offset = offset + 3
        tree:add(p_gm.fields.hs_certificates_len, v_certificates_len)

        local cts_len = v_certificates_len:uint() or 0
        if (cts_len ~= 0) then
            local v_certificates = tvb(offset, cts_len)
            local sub_cts = tree:add(p_gm.fields.hs_certificates, v_certificates)

            sub_cts:set_text("Certificates ("..cts_len.." bytes)")
            local i = 1
            while (i <= cts_len) do
                local v_certificate_len = tvb(offset, 3)
                offset = offset + 3
                sub_cts:add(p_gm.fields.hs_certificate_len, v_certificate_len)

                local v_certificate = tvb(offset, v_certificate_len:uint())
                offset = offset + v_certificate_len:uint()
                sub_cts:add(p_gm.fields.hs_certificate, v_certificate)
                i = i + 3 + v_certificate_len:uint()
            end
        end
    end

    local function hs_handler_ske(tvb, pinfo, tree)
        pinfo.cols.info = "ServerKeyExchange"
        local offset = 0

        local v_sign = tvb(offset, -1)
        tree:add(p_gm.fields.hs_ske_sign, v_sign)

    end

    local function hs_handler_cr(tvb, pinfo, tree)
        pinfo.cols.info = "Certificate Request"
        local offset = 0

        local v_cert_types_len = tvb(offset, 1)
        offset = offset + 1
        tree:add(p_gm.fields.hs_cert_types_len, v_cert_types_len)

        local cert_types_len = v_cert_types_len:uint() or 0
        if cert_types_len ~= 0 then
            local v_cert_types = tvb(offset, cert_types_len)
            local sub_cert_types = tree:add(p_gm.fields.hs_cert_types, v_cert_types)

            for i = 1, cert_types_len do
                local v_cert_type = tvb(offset, 1)
                offset  = offset + 1
                sub_cert_types:add(p_gm.fields.hs_cert_type, v_cert_type)
            end
        end

        local v_DNs_len = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_DNs_len, v_DNs_len)
        local DNs_len = v_DNs_len:uint() or 0
        if DNs_len ~= 0 then
            local v_DNs = tvb(offset, DNs_len)
            local sub_DNs = tree:add(p_gm.fields.hs_DNs, v_DNs)

            local i = 1
            while (i < DNs_len) do
                local v_DN_len = tvb(offset, 2)
                offset = offset + 2
                sub_DNs:add(p_gm.fields.hs_DN_len, v_DN_len)

                local v_DN = tvb(offset, v_DN_len:uint())
                offset = offset + v_DN_len:uint()
                sub_DNs:add(p_gm.fields.hs_DN, v_DN)

                i = i + 2 + v_DN_len:uint()
            end
        end
    end

    local function hs_handler_shd(tvb, pinfo, tree)
        pinfo.cols.info = "ServerHelloDone"
    end

    local function hs_handler_cv(tvb, pinfo, tree)
        pinfo.cols.info = "Certificate Verify"
        local offset = 0

        local v_cv_sign_len = tvb(offset, 2)
        offset = offset + 2
        tree:add(p_gm.fields.hs_cv_sign_len, v_cv_sign_len)

        local sign_len = v_cv_sign_len:uint()
        local v_cv_sign  = tvb(offset, sign_len)
        -- offset = offset + sign_len
        tree:add(p_gm.fields.hs_cv_sign, v_cv_sign)
    end

    local function hs_handler_cke(tvb, pinfo, tree)
    end
    local function hs_handler_fini(tvb, pinfo, tree)
    end

    local hs_handler = {
        [0] = hs_handler_hr,
        [1] = hs_handler_ch,
        [2] = hs_handler_sh,
        [11] = hs_handler_ct,
        [12] = hs_handler_ske,
        [13] = hs_handler_cr,
        [14] = hs_handler_shd,
        [15] = hs_handler_cv,
        [16] = hs_handler_cke,
        [20] = hs_handler_fini,
    }


    -- record content type
    function r_handler_ccs(tvb, pinfo, tree)
        local offset = 0

        tree:append_text("ChangeCipherSpec")
        pinfo.cols.info ="ChangeCipherSpec"
        return true
    end
    function r_handler_alert(tvb, pinfo, tree)
        local offset = 0

        tree:append_text("Alert: ")

        local t = tree:add(p_gm.fields.alert, tvb(offset, -1))

        local v_alert_level = tvb(offset, 1)
        offset = offset + 1
        t:add(p_gm.fields.alert_level, v_alert_level)

        local v_alert_desc = tvb(offset, 1)
        offset = offset + 1
        t:add(p_gm.fields.alert_desc, v_alert_desc)

        t:set_text("Alert: "..alert_levels[v_alert_level:uint()]..": "..alert_desc[v_alert_desc:uint()])
        pinfo.cols.info = "Alert: "..alert_levels[v_alert_level:uint()]..": "..alert_desc[v_alert_desc:uint()]

        return true
    end
    function r_handler_hs(tvb, pinfo, tree)
        local offset = 0

        tree:append_text("Handshake Protocol: ")
        local t = tree:add(p_gm.fields.hs, tvb(offset, -1))

        local v_type = tvb(offset, 1)
        offset = offset + 1
        t:add(p_gm.fields.hs_type, v_type)
        tree:append_text(hs_type[v_type:uint()])
        t:set_text("Handshake: "..hs_type[v_type:uint()])

        local v_len = tvb(offset, 3)
        offset = offset + 3
        t:add(p_gm.fields.hs_len, v_len)

        local handler = hs_handler[v_type:uint()]
        if (handler ~= nil) then
            handler(tvb(offset, -1):tvb(), pinfo, t)
        end

        return true;
    end
    function r_handler_app(tvb, pinfo, tree)
        -- TODO:
        return true
    end
    function r_handler_s2s(tvb, pinfo, tree)
        -- statements
        -- TODO:
        return true
    end

    local r_content_proto = {
        [20] = r_handler_ccs,
        [21] = r_handler_alert,
        [22] = r_handler_hs,
        [23] = r_handler_app,
        [80] = r_handler_s2s,
    }

    local data_dis = Dissector.get('tls')

    local function gm_dissector(tvb, pinfo, tree)
        local start = 0
        local offset = 0
        local total = tvb:len()
        local proto_added  = false
        local root = nil

        while (offset < total) do
            start = offset
            local v_r_type = tvb(offset, 1)
            offset = offset + 1
            local v_version = tvb(offset, 2)
            offset = offset + 2

            if (v_version:bytes():tohex() ~= "0101") then
                -- 不是GM协议
                return false
            end

            if proto_added ~= true then
                root = tree:add(p_gm, tvb)
                root:set_text("Transport Layer Security")
                pinfo.cols.protocol = 'GMv1.1'
                proto_added = true
            end

            local v_len = tvb(offset, 2)
            offset = offset + 2

            sub = root:add(p_gm.fields.record, tvb(start, v_len:uint()))
            sub:set_text("GMv1.1 Record Layer: ")
            sub:add(p_gm.fields.r_type,  v_r_type)
            sub:add(p_gm.fields.r_version, v_version)

            sub:add(p_gm.fields.r_len, v_len)

            local r_type_value = v_r_type:uint()
            local handler = r_content_proto[r_type_value]

            local ret = false
            if (handler ~= nil) then
                ret = handler(tvb(offset, v_len:uint()):tvb(), pinfo, sub)
                offset = offset + v_len:uint()
            end

            if ret ~= true then
                return false
            end
        end

        return true
    end

    function p_gm.dissector(tvb, pinfo, tree)
        if gm_dissector(tvb, pinfo, tree) then
            return
        else
            data_dis:call(tvb, pinfo, tree)
        end
    end

    local gm_table = DissectorTable.get('tcp.port')
    gm_table:add(8899, p_gm)

end