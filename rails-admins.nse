-- Lua single line comments.
-- HEAD SECTION

-- Brief description/purpose
description=[[
	Simple NMAP script to scan/enumerate Rails Admins page.
]]

-- Author
author = "Peter Benjamin"

-- Usage
---
-- nmap -p <port> --script rails-admins.nse <host>
--
-- @output
-- PORT		STATE	SERVICE
-- 3000/tcp	open	ppp
-- | rails-admins:
-- | 
-- | 
--

-- Imports
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"

local http = require "http"
local stdnse = require "stdnse"

-- RULE SECTION
portrule = shortport.http

-- ACTION SECTION
local DEFAULT_URI = "/admins"
local function check_rails_admin(host, port, path)
	local resp = http.get(host, port, path)
	if not http.response_contains(resp, "password") then
		return false
	end
	return true
end

action = function(host, port)
	local output = {}
	local vuln_rails = check_rails_admin(host, port, DEFAULT_URI)

	if not vuln_rails then
		stdnse.print_debug(1,"%s: This does not look like a vulnerable Rails app", SCRIPT_NAME)
		return
	end
end
