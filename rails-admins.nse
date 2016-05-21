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
-- | <td>PeterBenjamin</td>
-- | <td>MySuperSecr3t</td> 
--

-- Imports
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

-- RULE SECTION
portrule = function(host, port)
  local auth_port = { number=3000, protocol="tcp" }
  local identd = nmap.get_port_state(host, auth_port)

  return identd ~= nil
    and identd.state == "open"
    and port.protocol == "tcp"
    and port.state == "open"
end

-- ACTION SECTION
local DEFAULT_URI = "/admins"
local function check_rails_admin(host, port, path)
	local resp = http.get(host, port, path)
	if not http.response_contains(resp, "password") then
		return false
	end
	return resp
end

action = function(host, port)
	local vuln_rails = check_rails_admin(host, port, DEFAULT_URI)
  local output = {}
	if not vuln_rails then
		stdnse.print_debug(1,"%s: This does not look like a vulnerable Rails app", SCRIPT_NAME)
		return
  else
    output = string.match(vuln_rails["body"], "%<td%>.*%<%/td%>")
	end
  return output
end
