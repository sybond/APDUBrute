-- @name Brute force APDU SELECT
-- @description Sending brute force 2 bytes APDU SELECT 0x0000 - 0xFFFF
-- @targets 0.8
-- Version 1.1
-- Copyright (c) 2014 Bond Computer Systems
-- Written by Bondan Sumbodo


require('lib.strict')
require('lib.apdu')
if card.connect() then
	CRoot=card.tree_startup("Processing Bruteforce..")
	log.print(log.INFO,"Brute force SELECT start")
	for i=0x0000,0xFFFF,1 do
		cmd=bytes.new(8,0x00,0xA4,0x00,0x00,0x02,bit.SHR(i,8),bit.AND(i,0xFF))
		sw, resp = card.send(cmd)
		if (sw==0x9000) then
			-- Approved response on SELECT			
			APVnod=nodes.append(CRoot, {classname="record",label="Approved CAPDU",val=cmd})
			nodes.append(APVnod, {classname="item",label="Received RAPDU data",val=bytes.format(resp,"%D")})
			-- Trying to send BINARY READ for first 8 bytes
			sw, resp = card.send(bytes.new(8, "00 B0 00 00 08"))
		end
	end
	log.print(log.INFO,"Brute force SELECT end")
card.disconnect()
end
