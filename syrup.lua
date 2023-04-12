-------------------
-- External APIs --
-------------------

local sha = require("dependencies/sha256") -- https://pastebin.com/6UV4qfNF
local ecc = require("dependencies/ecc") -- https://www.computercraft.info/forums2/index.php?/topic/29803-elliptic-curve-cryptography/

-- Syrup Framework, Copyright 2023, by R The sombrero man

local srp = {...}

-- Error types
local conformityError = " does not conform to expected value"
local existenceError = " does not exist or could not be found"

-- Text Based Graphics
local w,h = term.getSize()

function srp.align(str, align, mode)
	local x,y = term.getCursorPos()

	assert(type(str) == "string", "passed argument 1"..conformityError)
	assert(align == "left" or align == "center" or align == "centre" or align == "right", "passed argument 2"..conformityError)
	assert(mode == "write" or mode == "w" or mode == "print" or mode == "p", "passed argument 3"..conformityError)

	if mode == "write" or mode == "w" then
		if align == "left" then
			term.setCursorPos(1,y)
		elseif align == "right" then
			term.setCursorPos(w-string.len(str), y)
		else
			term.setCursorPos((w-string.len(str))/2, y)
		end
		term.write(str)
	else
		if align == "left" then
			term.setCursorPos(1,y)
		elseif align == "right" then
			term.setCursorPos(w-string.len(str), y)
		else
			term.setCursorPos((w-string.len(str))/2, y)
		end
		print(str)
	end
end

function srp.textLoop(str, n, mode)

	assert(type(str) == "string", "passed argument 1"..conformityError)
	assert(type(n) == "number", "passed argument 2"..conformityError)
	assert(mode == "w" or mode == nil, "passed optional argument 3"..conformityError)

	for i = 1, n do
		term.write(str)
	end
	if mode then
		print("")
	end
end

function srp.buildInteractive(options, results)
	local selected = 1

	assert(type(options) == "table", "passed argument 1"..conformityError)
	assert(type(results) == "table", "passed argument 2"..conformityError)


	while true do
		for opK, opV in pairs(options) do
			term.setCursorPos(1, math.floor((h-math.floor(#options))/2+opK))
			srp.align((selected == opK and "[ "..opV.." ]") or "  "..opV.."  ", "center", "p")
		end
		local event, key = os.pullEvent("key")
		if key == keys.up then
			if selected == 1 then
				selected = #options
			else
				selected = selected - 1
			end
		elseif key == keys.down then
			if selected == #options then
				selected = 1
			else
				selected = selected + 1
			end
		elseif key == keys.enter then
			break
		end
	end
	results[selected]()
end

function srp.buildHeader()
	term.setCursorPos(1,1)
	term.write("Telecall 0.1")
	term.setTextColor(colors.red)
	srp.align("Alpha", "right", "p")
	term.setTextColor(colors.white)
	srp.textLoop("=", w)
end

function srp.fileText(dir,y, align)
	term.setCursorPos(1,y)
	if fs.exists(dir) then
		local asciiRead = fs.open(dir, "r")
		local lines = asciiRead.readLine()
		local asciiData = {}
		for lines in asciiRead.readLine do
			srp.align(lines, align, "p")
		end
		asciiRead.close()
	else
		error("directory"..conformityError)
	end
end

-- Networking

function srp.certAuthInit(path) -- iniatilise certificate authority
	term.clear()
	term.setCursorPos(1,1)
	print("Syrup API certAuthInit")

	if not fs.exists("certAuth/keypair.key") then -- if a keypair hasn't already been generated, generate one
		print("Keypair not found. Creating...")
		local keyWrite = fs.open("certAuth/keypair.key", "w")
		local certSecretKey, certPublicKey = ecc.keypair(ecc.random.random())
		local keyPair = {tostring(certSecretKey), tostring(certPublicKey)}
		keyWrite.write(textutils.serialize(keyPair))
		keyWrite.close()
	end
	local keyRead = fs.open("certAuth/keypair.key", "r")
	local certKeyPair = textutils.unserialize(keyRead.readAll())
	keyRead.close()

	local certSecretKey = certKeyPair[1]
	local certPublicKey = certKeyPair[2]

	print("Keypair gathered from keyfile")
	if fs.exists(path) then
		print("Found "..path)
		local certRead = fs.open(path, "r")

		local unsignedServer = textutils.unserialize(certRead.readAll())
		print(unsignedServer)
		certRead.close()

		local signature = ecc.sign(certSecretKey, unsignedServer)
		local signedServer = {}
		signedServer["unsignedCert"] = unsignedServer
		signedServer["signature"] = signature
		signedServer["certAuthPublic"] = tostring(certPublicKey)

		certWrite = fs.open(path, "w")
		certWrite.write(textutils.serialize(unsignedServer))
		certWrite.close()
	else
		error("path"..existenceError)
	end
end
-- unsigned server cert format:

-- {
-- 	serverName: string
-- 	serverPublicKey: string
-- }

-- signed server cert format:
-- {
-- 	unsignedCert: table
-- 	signature: string
--  certAuthPublic: string
-- }


function srp.nameToAddress(name)
	assert(type(name) == "string", "name"..conformityError)

	local hashedName = sha.digest(name)

	local nameTable = {}
	local address = 0
	for i = 1, #hashedName do
		nameTable[i] = hashedName:sub(i, i)
	end

	if string.len(hashedName) >= 3 then
		for p = 1, 3 do
			address = address..nameTable[p]:byte()
		end
	else
		for q = 1, #nameTable do
			address = address..nameTable[q]:byte()
		end
	end
	address = tonumber(address:sub(2, 6))

	if address >= 65535 then  -- modem api prevents frequency > 65535
		address = tonumber(tostring(address):sub(1, 4))
	elseif address <= 99 then -- lower band likely taken up by Rednet
		address = address*100
	end

	return address
end

-- name     - name of the server, used by clients to connect
-- certPath - path to the server.cert file, if it exists (else create one)
-- keyPath  - path to the keypair.key file, if it exists (else create one)
-- secure   - whether players are required to log-in to initiate a tunnel
function srp.host(name, secure, certPath, keyPath)
	assert(type(name) == "string", "name"..conformityError)
	assert(type(certPath) == "string" or certPath == nil, "certPath"..conformityError)
	assert(type(keyPath) == "string" or keyPath == nil, "keyPath"..conformityError)
	assert(type(secure) == "boolean" or secure == nil, "secure"..conformityError)

	-- create "address" -- this address is used to connect behind the scenes
	local address = srp.nameToAddress(name)
	print("Internal server address: "..address)

	-- gather keys
	if keyPath == nil then -- if doesn't exist, generate in standard directory: server/keypair.key
		serverSecretKey, serverPublicKey = ecc.keypair(ecc.random.random())
		keyPair = {tostring(serverSecretKey), tostring(serverPublicKey)}

		local writeHandle = fs.open("server/keypair.key", "w")
		writeHandle.write(textutils.serialize(keyPair))
		writeHandle.close()

	else
		local readHandle = fs.open("keyPath", "r")
		keyPair = textutils.unserialize(readHandle.readAll())
		readHandle.close()

		serverSecretKey = keyPair[1]
		serverPublicKey = keyPair[2]
	end

	if certPath == nil then -- if a certificate has not been provided, generate one
		print("No certificate has been provided, generating one")
		local writeHandle = fs.open("server/server.cert", "w")

		certificate = {}
		certificate["serverName"] = name
		certificate["serverPublicKey"] = tostring(serverPublicKey)
		writeHandle.write(textutils.serialize(certificate))
		writeHandle.close()
	elseif not fs.exists(certPath) then
		error("certPath"..existenceError)
	else
		local readHandle = fs.open(certPath, "r")

		certificate = textutils.unserialize(readHandle.readAll())
		readHandle.close()
	end
	if certificate["signature"] == nil then
		term.setTextColor(colors.red)
		term.write("!WARNING! ")
		term.setTextColor(colors.white)
		print("Certificate is not signed by certAuth")
	end

	if not secure then
		term.setTextColor(colors.red)
		term.write("!WARNING! ")
		term.setTextColor(colors.white)
		print("Server is being generated without log-in requirement. This is not recommended.")
	else
		if fs.exists("server/users.hdb") then
			print("Found user table")
			local readHandle = fs.open("server/users.hdb", "r")
			local authUsers = textutils.unserialize(readHandle.readAll())
			readHandle.close()
		else
			term.setTextColor(colors.red)
			term.write("!WARNING! ")
			term.setTextColor(colors.white)
			print("'server/users.hdb' not found. Creating...")
			local writeHandle = fs.open("server/users.hdb", "w")
			writeHandle.close()
		end
	end
	local modem = peripheral.find("modem")
	if not modem then error("No modem attached", 2) end
	modem.open(address)
end

function srp.resolveConnections(address, secure, certPath)
	assert(type(address) == "number", "address"..conformityError)
	assert(type(secure) == "boolean" or secure == nil, "secure"..conformityError)
	assert(fs.exists(certPath), "certPath"..conformityError..". Has it been generated?")

	if not modem then
		local modem = peripheral.find("modem")
		if not modem then error("No modem attached", 2) end
	end

	if not modem.isOpen(address) then modem.open(address) end
	while true do
		local event, side, freq, replyFreq, msg = os.pullEvent("modem_message")
		if msg == "connection_request" then
			local readHandle = fs.open(certPath, "r")
			local certificate = readHandle.readAll()
			local payloadTable = {}
			payloadTable["secure"] = secure
			payloadTable["cert"] = certificate
			local handshakePayload = textutils.serialize(payloadTable)
			readHandle.close()
			modem.transmit(replyFreq, freq, handshakePayload)
		end
	end
end

function srp.connect(name, user, hashPass)
	assert(type(name) == "string", "name"..conformityError)
	assert(type(user) == "string" or user == nil, "user"..conformityError)
	assert(type(hashPass) == "string" or hashPass == nil, "hashPass"..conformityError)

	local address = srp.nameToAddress(name)
	local modem = peripheral.find("modem")
	if not modem then error("No modem attached", 2) end
	modem.open(address)

	modem.transmit(address, address, "connection_request")
	while true do
		local event, side, replyFreq, freq, handshakePayload = os.pullEvent("modem_message")
		if handshakePayload["cert"]["signature"] then -- if signature exists
			if not ecc.verify(handshakePayload["cert"]["certAuthPublic"], handshakePayload["cert"]["unsignedCert"], handshakePayload["cert"]["signature"]) then
				return -- certificate forged => terminate transaction
			end
			local loginDetails = {}
			loginDetails["user"] = user
			loginDetails["hashPass"] = hashPass
			loginDetails = textutils.serialize(loginDetails)
			modem.transmit(freq, replyFreq, loginDetails)
		end
	end
end

-- End Syrup Framework
return srp