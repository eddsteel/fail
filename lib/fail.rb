#!/usr/bin/ruby -w
# fail.rb
#
# Thanks to:
# - kaiwren's wrest facebook example. (TODO: URL)
# - Łukasz Pełsziński's blog post: Facebook REST API: The 
#   hacker's way. (TODO: URL)
#
# Copyright (C) 2010 Edd Steel (edward.steel@gmail.com)
#
# Free software released under the GNU GPL 
# version 3 or later (see LICENSE)
#
# TODO
# - Recognise error responses

require 'net/http'
require 'net/https'
require 'cgi'
require 'rexml/document'

# Facebook Application Integration Layer
module FAIL
  module XML
    def parse(xml)
      REXML::Document.new(xml)
    end

    # allow [] with strings to look-up xpaths.
    class REXML::Element
      alias :oldarr :[]

      def [](xpath, &block)
        if xpath.kind_of? String
          REXML::XPath.each(self, xpath, &block)
        else
          self.oldarr(xpath, &block)
        end
      end
    end

    module_function :parse
  end

  class Facebook
    include XML

    @@KEY = @@SECRET = nil

    # To set the key and secret either
    # store FAIL::Facebook.KEY and
    # FAIL::Facebook.SECRET or provide them here.
    def initialize(key=@@KEY, secret=@@SECRET)
      raise "KEY and SECRET must be set in FAIL::Facebook" if key.nil? || secret.nil?
      @key = key
      @secret = secret
    end

    # Authenticate, providing better access to API
    # In order, this method:
    # visits login page to get required cookies
    # posts to the auth.createToken to get an auth_token
    # uses cookies and auth_token to fake a web login
    # requests a session for that auth token (granted,
    # because the user has logged in) 
    def login(email, password)
      http = https('login.facebook.com')
      headers = {}
      headers['User-Agent'] = @@USER_AGENT

			cookie_header = form_cookie_header(http.get('/login.php', headers).response['Set-Cookie'])
			puts "cookie_header is #{cookie_header}"

      headers['Cookie'] =  cookie_header
 			headers['Content-Type'] = 'application/x-www-form-urlencoded'

      data = {}
      data[:api_key] = @key
      data[:email] = CGI::escape(email)
      data[:pass] = CGI::escape(password)
      data[:auth_token] = XML::parse(post('auth.createToken').body)['/auth_createToken_response/[]'].first.to_s
			puts data[:auth_token]

      # fake log-in
      post(nil, data, 'login.facebook.com', '/login.php?login_attempt=1', headers)
			#
      # request session on same token
      doc = XML::parse(post('auth.getSession', :auth_token=>data[:auth_token]).body)
			debug(doc.to_s)

      @session_key = doc['//session_key'].first.text
      @secret = doc['//secret'].first.text
      @uid = doc['//uid'].first.text
    end


    # get csv list of available friend uids
    def get_friends(uid=@uid)
      doc = XML::parse(post('friends.get', :uid=>uid).body)
      doc['//uid'].map {|tag| tag.text}.join(',')
    end


    def post(operation, args={}, host=@@HOST, endpoint=@@ENDPOINT, headers={})
      if operation #facebook call
        operation = "facebook.#{operation}" unless operation.start_with? 'facebook.'
        args[:method] = operation
        args[:api_key] = @key
        args[:call_id] = Time.new.to_f.to_s
        args[:v] = '1.0'
        args[:session_key] = @session_key if @session_key
        args[:sig] = sign(args)
        debug "Calling #{operation} on Facebook"
      else
        debug "Performing simple POST"
      end

      http = https(host)
      headers['User-Agent'] = @@USER_AGENT
			headers['Content-Type'] = 'application/x-www-form-urlencoded'
      data_string = args.map{|k,v| "#{k.to_s}=#{v}" }.join('&')
      debug("posting #{data_string} to #{endpoint} with headers: #{headers}")
      response = http.post(endpoint, data_string, headers).response
			# thanks for the use of HTTP response codes facebook.
			if /.*<error_response.*/ =~ response.body
				handle_error response.body
			end
			response
    end

		def handle_error(doc)
			doc = XML::parse(doc)
			code = doc['error_response/error_code/[]'].first.to_s
			status = doc['error_response/error_msg/[]'].first.to_s
			debug("Error #{code}: #{status}")
			debug(doc['//request_args'].first.to_s)
			raise FacebookError, "Facebook said: Error #{code}: #{status}", caller
		end

    def method_missing(method, *args)
      	Poster.new(self, method.to_s)
    end


    private 
    
    # quick and dirty cookie extraction
    # Converts value from 'Set-Cookie' header to value suitable for 'Cookie'
    # header
    def form_cookie_header(cookies)
      cookies.scan(/(?:, |^)(\w+=[\w%-]+)/).flatten.join('; ')
    end


    def sign(args, secret=@secret)
			debug "secret is #{secret}"
      strings = {}
      args.each {|k,v| strings[k.to_s] = v}
      arg_string = strings.sort.map {|k,v| "#{k}=#{v}"}.join
      Digest::MD5.hexdigest arg_string + secret
    end

    def https(host)
      http = Net::HTTP.new(host, 443)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
			http
    end
    
    # implements 'facebook.<category>.<method>' calls
    class Poster
      def initialize(facebook, category)
        @facebook = facebook
        @category = category
      end

      def method_missing(method, *args)
        method_parts = ['facebook', @category, method.to_s]
        @facebook.post(method_parts.join('.'), *args)
      end
    end

    @@HOST = 'api.facebook.com'
    @@ENDPOINT = '/restserver.php?'
    @@USER_AGENT='Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.7) Gecko/20100106 Ubuntu/9.10 (karmic) Firefox/3.5.7'

		def persevere(&block)
			retry_count = 0
			begin
				retry_count++
				yield
			rescue SocketError
				retry if retry_count < 3
				raise FacebookError, "Unable to contact Facebook. Please check your connection", caller
			end
		end
  end

	class Profile
		@@fields = %w[uid name]

		attr_reader :id, :name

		def initialize(id, name)
      @id = id
      @name = name
		end

    def self.find(fb, id)
      self.find_all(fb, id)[0]
    end

		# Finds and creates a profile for each uid. The profiles
		# can be further limited with the &filter block, which
		# should take one parameter (the profile's XML element) 
		# which it can interrogate to decide whether to proceed (it
		# returns true) or skip (it returns false)
		# This method expects the profile's initialize method to
		# accept the same number of arguments and in the same order
		# as the @@fields variable, but they needn't be called the same.
		# 
    def self.find_all(fb, uids=fb.get_friends, &filter)
      debug("finding profiles of #{uids}.")
      doc = XML::parse(fb.users.getInfo(
        :fields=>@@fields.join(','), :uids=>uids).body)

      profiles = doc['//user'].map do |tag|
        tag = tag.to_s
        if filter.call(tag)
          fields = @@fields.map do |field|
            $1 if tag =~ %r{<#{field}>([^<]*)</#{field}>}
          end 
          self.new(*fields)
        end
      end

      profiles.compact
    end
	end

	class FacebookError < StandardError
	end

  def debug(msg)
    puts "[FB] " << msg if $DEBUG
  end

  module_function :debug
end
