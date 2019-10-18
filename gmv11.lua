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
    p_gm.fields.type = ProtoField.uint8('tls.record.type', 'Content Type', base.DEC, r_content_type)
    p_gm.fields.version = ProtoField.uint16('tls.record.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_gm.fields.len = ProtoField.uint16("tls.record.length", "Length", base.DEC)

    local p_ccs   = Proto("changecipherspec", "ChangeCipherSpec")
    local p_alert = Proto("alert","Alert")
    local p_hs    = Proto('handshake','Handshake')
    local p_app   = Proto('applicationdata','ApplicationData')
    local p_s2s   = Proto('site2site','Site2site')

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

    p_hs.fields.type = ProtoField.uint8("tls.handshake.type", "Handshake Type", base.DEC, hs_type)
    p_hs.fields.len  = ProtoField.uint24("tls.handshake.length", "Length", base.DEC)
    p_hs.fields.version  = ProtoField.uint16('tls.handshake.version', 'Version', base.HEX, {[0x0101] = 'GM v1.1'})
    p_hs.fields.random = ProtoField.bytes('tls.handshake.random', 'Random', base.NONE)
    p_hs.fields.gmt_time = ProtoField.absolute_time('tls.handshake.gmt_time', 'GMT Unix Time', base.LOCAL)
    p_hs.fields.real_random = ProtoField.bytes('tls.handshake.real_random', 'Random Bytes', base.NONE)

    local function hs_handler_ch(tvb, pinfo, tree)
        local offset = 0
        local v_version = tvb(offset, 2)
        offset = offset + 2

        tree:add(p_hs.fields.version, v_version)

        local v_random = tvb(offset, 32)
        local t = tree:add(p_hs.fields.random, v_random)
        local v_gmt_time = tvb(offset, 4)
        offset = offset + 4
        t:add(p_hs.fields.gmt_time, v_gmt_time)
        local v_real_random = tvb(offset, 28)
        offset = offset + 28
        t:add(p_hs.fields.real_random, v_real_random)


        -- todo: client_hello
    end

    local function hs_handler_sh(tvb, pinfo, tree)

    end
    local hs_handler = {
        [1] = hs_handler_ch,
        [2] = hs_handler_sh,
    }




    -- record content type
    local PContentType = {
        type = 0,
        name = nil,
        proto = nil,
        handler = nil,
    }

    function PContentType:new(o, type, name, proto)
        o = o or {}
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o
    end

    function PContentType:handle(tvb, pinfo, tree)
        -- statements
    end

    local PContentType_CCS = PContentType:new()
    local PContentType_ALERT = PContentType:new()
    local PContentType_HS = PContentType:new()
    local PContentType_APP = PContentType:new()
    local PContentType_S2S =  PContentType:new()

    function PContentType_CCS:new(o, type, name, proto)
        o = o or PContentType:new(o)
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o;
    end
    function PContentType_CCS:handle(tvb, pinfo, tree)
        -- statements
        -- TODO:
        print(self.name)
        return true
    end


    function PContentType_ALERT:new(o, type, name, proto)
        o = o or PContentType:new(o)
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o;
    end
    function PContentType_ALERT:handle(tvb, pinfo, tree)
        -- statements
        -- TODO:
        print(self.name)
        return true
    end


    function PContentType_HS:new(o, type, name, proto)
        o = o or PContentType:new(o)
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o;
    end
    function PContentType_HS:handle(tvb, pinfo, tree)
        local offset = 0
        local t = tree:add(self.proto, tvb)

        local v_type = tvb(offset, 1)
        offset = offset + 1
        t:add(p_hs.fields.type, v_type)
        t:append_text(": "..hs_type[v_type:uint()])

        local v_len = tvb(offset, 3)
        offset = offset + 3
        t:add(p_hs.fields.len, v_len)


        local handler = hs_handler[v_type:uint()]
        if (handler ~= nil) then
            handler(tvb(offset, -1):tvb(), pinfo, t)
        end


        return true;
    end

    function PContentType_APP:new(o, type, name, proto)
        o = o or PContentType:new(o)
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o;
    end
    function PContentType_APP:handle(tvb, pinfo, tree)
        -- TODO:
        print(self.name)
        return true
    end

    function PContentType_S2S:new(o, type, name, proto)
        o = o or PContentType:new(o)
        setmetatable(o, self)
        self.__index = self
        self.type = type
        self.name = name
        self.proto = proto
        return o;
    end
    function PContentType_S2S:handle(tvb, pinfo, tree)
        -- statements
        -- TODO:
        print(self.name)
        return true
    end

    local r_content_proto = {
        [20] = PContentType_CCS:new(nil, 20, p_ccs.name, p_ccs),
        [21] = PContentType_ALERT:new(nil, 21, p_alert.name, p_alert),
        [22] = PContentType_HS:new(nil, 22, p_hs.name, p_hs),
        [23] = PContentType_APP:new(nil, 23, p_app.name, p_app),
        [80] = PContentType_S2S:new(nil, 80, p_s2s.name, p_s2s),
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
        root:add(p_gm.fields.type,  v_r_type)
        root:add(p_gm.fields.version, v_version)

        local v_len = tvb(offset, 2)
        offset = offset + 2
        root:add(p_gm.fields.len, v_len)

        local r_type_value = v_r_type:le_uint()
        local proto = r_content_proto[r_type_value]
        if (proto ~= nil) then
            print("nihao "..proto.name.." "..r_type_value)
            return proto:handle(tvb(offset,-1):tvb(), pinfo, root)
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