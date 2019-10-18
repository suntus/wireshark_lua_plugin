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
    p_gm.fields.r_type = ProtoField.uint8('tls.record.type', 'Content Type', base.DEC, r_content_type)
    p_gm.fields.r_version = ProtoField.uint16('tls.record.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_gm.fields.r_len = ProtoField.uint16("tls.record.length", "Length", base.DEC)

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
    p_gm.fields.hs = ProtoField.bytes("tls.record.content", "Handshake", base.NONE)
    p_gm.fields.hs_type = ProtoField.uint8("tls.handshake.type", "Handshake Type", base.DEC, hs_type)
    p_gm.fields.hs_len  = ProtoField.uint24("tls.handshake.length", "Length", base.DEC)
    p_gm.fields.hs_version  = ProtoField.uint16('tls.handshake.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_gm.fields.hs_random = ProtoField.bytes('tls.handshake.random', 'Random', base.NONE)
    p_gm.fields.hs_gmt_time = ProtoField.absolute_time('tls.handshake.gmt_time', 'GMT Unix Time', base.LOCAL)
    p_gm.fields.hs_random_bytes = ProtoField.bytes('tls.handshake.random_bytes', 'Random Bytes', base.NONE)
    p_gm.fields.hs_sess_id_len = ProtoField.uint8('tls.handshake.session_id_len', 'Session ID Length', base.DEC)
    p_gm.fields.hs_sess_id = ProtoField.bytes('tls.handshake.session_id', 'Session ID', base.NONE)
    p_gm.fields.hs_cipher_suites_len = ProtoField.uint8('tls.handshake.cipher_suites_len', 'Cipher Suites Length', base.DEC)
    p_gm.fields.hs_ciphers = ProtoField.bytes('tls.handshake.ciphers', 'Session ID', base.NONE)

    local function hs_handler_ch(tvb, pinfo, tree)
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

        local v_cihpers_len
    end
    local function hs_handler_sh(tvb, pinfo, tree)

    end
    local hs_handler = {
        [1] = hs_handler_ch,
        [2] = hs_handler_sh,
    }


    -- record content type
    function r_handler_ccs(tvb, pinfo, tree)
        -- statements
        -- TODO:
        return true
    end
    function r_handler_alert(tvb, pinfo, tree)
        -- statements
        -- TODO:
        return true
    end
    function r_handler_hs(tvb, pinfo, tree)
        local offset = 0
        local t = tree:add(p_gm.fields.hs, tvb(offset, -1))

        local v_type = tvb(offset, 1)
        offset = offset + 1
        t:add(p_gm.fields.hs_type, v_type)
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
        local root = tree:add(p_gm, tvb)

        local offset = 0
        local v_r_type = tvb(offset, 1)
        offset = offset + 1
        local v_version = tvb(offset, 2)
        offset = offset + 2

        if (v_version:bytes():tohex() ~= "0101") then
            -- 不是GM协议
            return false
        end

        pinfo.cols.protocol = 'GMv1.1'
        root:add(p_gm.fields.r_type,  v_r_type)
        root:add(p_gm.fields.r_version, v_version)

        local v_len = tvb(offset, 2)
        offset = offset + 2
        root:add(p_gm.fields.r_len, v_len)

        local r_type_value = v_r_type:le_uint()
        local handler = r_content_proto[r_type_value]
        if (handler ~= nil) then
            return handler(tvb(offset, -1):tvb(), pinfo, root)
        end

        return false
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