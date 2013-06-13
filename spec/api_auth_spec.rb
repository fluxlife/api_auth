require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "ApiAuth" do

  describe "generating secret keys" do

    it "should generate secret keys" do
      ApiAuth.generate_secret_key
    end

    it "should generate secret keys that are 89 characters" do
      ApiAuth.generate_secret_key.size.should be(89)
    end

    it "should generate keys that have a Hamming Distance of at least 65" do
      key1 = ApiAuth.generate_secret_key
      key2 = ApiAuth.generate_secret_key
      Amatch::Hamming.new(key1).match(key2).should be > 65
    end

  end

  describe "signing requests" do

    def hmac(secret_key, request)
      canonical_string = ApiAuth::Headers.new(request).canonical_string
      digest = OpenSSL::Digest::Digest.new('sha1')
      ApiAuth.b64_encode(OpenSSL::HMAC.digest(digest, secret_key, canonical_string))
    end

    before(:all) do
      @access_id = "1044"
      @secret_key = ApiAuth.generate_secret_key
    end

    describe "with Net::HTTP" do

      before(:each) do
        @request = Net::HTTP::Put.new("/resource.xml?foo=bar&bar=foo", 
          'content-type' => 'text/plain', 
          'content-md5' => '1B2M2Y8AsgTpgAmY7PhCfg==',
          'date' => Time.now.utc.httpdate)
        @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)

        @request_with_nonce = Net::HTTP::Put.new("/resource.xml?foo=bar&bar=foo", 
          'content-type' => 'text/plain', 
          'content-md5' => '1B2M2Y8AsgTpgAmY7PhCfg==',
          'date' => Time.now.utc.httpdate)
        @signed_request_with_nonce = ApiAuth.sign!(@request_with_nonce, @access_id, @secret_key, :use_nonce=>true)
      end

      it "should return a Net::HTTP object after signing it" do
        ApiAuth.sign!(@request, @access_id, @secret_key).class.to_s.should match("Net::HTTP")
      end

      describe "md5 header" do
        context "not already provided" do
          it "should calculate for empty string" do
            request = Net::HTTP::Put.new("/resource.xml?foo=bar&bar=foo",
              'content-type' => 'text/plain',
              'date' => "Mon, 23 Jan 1984 03:29:56 GMT")
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request['Content-MD5'].should == Digest::MD5.base64digest('') => Doesn't work in ruby 1.8.7
            signed_request['Content-MD5'].should == Base64.encode64(Digest::MD5.digest('')).strip
          end

          it "should calculate for real content" do
            request = Net::HTTP::Put.new("/resource.xml?foo=bar&bar=foo",
              'content-type' => 'text/plain',
              'date' => "Mon, 23 Jan 1984 03:29:56 GMT")
            request.body = "hello\nworld"
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request['Content-MD5'].should == Digest::MD5.base64digest("hello\nworld") => Doesn't work in ruby 1.8.7
            signed_request['Content-MD5'].should == Base64.encode64(Digest::MD5.digest("hello\nworld")).strip
          end
        end

        it "should leave the content-md5 alone if provided" do
          @signed_request['Content-MD5'].should == '1B2M2Y8AsgTpgAmY7PhCfg=='
        end
      end

      it "should sign the request" do
        @signed_request['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request)}"
      end

      it "should sign the request with a nonce" do
        @signed_request_with_nonce['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request_with_nonce)}&NONCE:#{ApiAuth.generate_nonce(@request_with_nonce, @secret_key)}"
      end

      it "should authenticate a valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key).should be_true
      end

      it "should authenticate a valid request with a nonce" do
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key, :check_nonce=>true).should be_true
      end

      it "should NOT authenticate a non-valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key+'j').should be_false
      end

      it "should NOT authenticate a valid request with an invalid nonce" do
        @signed_request_with_nonce["DATE"] = 1.second.from_now.utc.httpdate
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key).should be_false
      end

      it "should NOT authenticate a mismatched content-md5 when body has changed" do
        request = Net::HTTP::Put.new("/resource.xml?foo=bar&bar=foo",
          'content-type' => 'text/plain',
          'date' => "Mon, 23 Jan 1984 03:29:56 GMT")
        request.body = "hello\nworld"
        signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
        signed_request.body = "goodbye"
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate an expired request" do
        @request['Date'] = 16.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate a custom expired request" do
        @request['Date'] = 5.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key, :ttl=>4.minutes.to_i).should be_false
      end
      
      it "should retrieve the access_id" do
        ApiAuth.access_id(@signed_request).should == "1044"
      end

      it "should retrieve the nonce_value" do
        ApiAuth.nonce_value(@signed_request_with_nonce).should == ApiAuth.generate_nonce(@request_with_nonce,@secret_key)
      end

    end

    describe "with RestClient" do

      before(:each) do
        headers = { 'Content-MD5' => "1B2M2Y8AsgTpgAmY7PhCfg==",
                    'Content-Type' => "text/plain",
                    'Date' => Time.now.utc.httpdate }
        @request = RestClient::Request.new(:url => "/resource.xml?foo=bar&bar=foo", 
          :headers => headers,
          :method => :put)
        @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)

        #  Need to create specific set of headers because identical RestClient requests get merged
        #  into one request.
        nonce_headers = { 'Content-MD5' => "1B2M2Y8AsgTpgAmY7PhCfg==",
                    'Content-Type' => "text/plain",
                    'Date' => 5.seconds.ago.utc.httpdate }
        @request_with_nonce =RestClient::Request.new(:url => "/resource.xml?foo=bar&bar=foo", 
          :headers => nonce_headers,
          :method => :put)
        @signed_request_with_nonce = ApiAuth.sign!(@request_with_nonce, @access_id, @secret_key, :use_nonce=>true)
      end

      it "should return a RestClient object after signing it" do
        ApiAuth.sign!(@request, @access_id, @secret_key).class.to_s.should match("RestClient")
      end

      describe "md5 header" do
        context "not already provided" do
          it "should calculate for empty string" do
            headers = { 'Content-Type' => "text/plain",
                        'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
            request = RestClient::Request.new(:url => "/resource.xml?foo=bar&bar=foo",
              :headers => headers,
              :method => :put)
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.headers['Content-MD5'].should == Digest::MD5.base64digest('') => Doesn't work in ruby 1.8.7
            signed_request.headers['Content-MD5'].should == Base64.encode64(Digest::MD5.digest('')).strip
          end

          it "should calculate for real content" do
            headers = { 'Content-Type' => "text/plain",
                        'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
            request = RestClient::Request.new(:url => "/resource.xml?foo=bar&bar=foo",
              :headers => headers,
              :method => :put,
              :payload => "hellow\nworld")
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.headers['Content-MD5'].should == Digest::MD5.base64digest("hellow\nworld") => Doesn't work in ruby 1.8.7
            signed_request.headers['Content-MD5'].should == Base64.encode64(Digest::MD5.digest("hellow\nworld")).strip
          end
        end

        it "should leave the content-md5 alone if provided" do
          @signed_request.headers['Content-MD5'].should == "1B2M2Y8AsgTpgAmY7PhCfg=="
        end
      end

      it "should sign the request" do
        @signed_request.headers['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request)}"
      end

      it "should sign the request with a nonce" do
        @signed_request_with_nonce.headers['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request_with_nonce)}&NONCE:#{ApiAuth.generate_nonce(@request_with_nonce, @secret_key)}"
      end      

      it "should authenticate a valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key).should be_true
      end

      it "should authenticate a valid request with a nonce" do
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key, :check_nonce=>true).should be_true
      end

      it "should NOT authenticate a non-valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key+'j').should be_false
      end

      it "should NOT authenticate a valid request with an invalid nonce" do
        @signed_request_with_nonce.headers["DATE"] = 1.second.from_now.utc.httpdate
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key).should be_false
      end

      it "should NOT authenticate a mismatched content-md5 when body has changed" do
        headers = { 'Content-Type' => "text/plain",
                    'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
        request = RestClient::Request.new(:url => "/resource.xml?foo=bar&bar=foo",
          :headers => headers,
          :method => :put,
          :payload => "hello\nworld")
        signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
        signed_request.instance_variable_set("@payload", RestClient::Payload.generate('goodbye'))
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate an expired request" do
        @request.headers['Date'] = 16.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate a custom expired request" do
        @request.headers['Date'] = 5.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key, :ttl=>4.minutes.to_i).should be_false
      end
      
      it "should retrieve the access_id" do
        ApiAuth.access_id(@signed_request).should == "1044"
      end

      it "should retrieve the nonce_value" do
        ApiAuth.nonce_value(@signed_request_with_nonce).should == ApiAuth.generate_nonce(@request_with_nonce,@secret_key)
      end

    end

    describe "with Curb" do

      before(:each) do
        headers = { 'Content-MD5' => "e59ff97941044f85df5297e1c302d260",
                    'Content-Type' => "text/plain",
                    'Date' => Time.now.utc.httpdate }
        @request = Curl::Easy.new("/resource.xml?foo=bar&bar=foo") do |curl|
          curl.headers = headers
        end
        @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)


        #  Need to create specific set of headers because identical RestClient requests get merged
        #  into one request.
        nonce_headers = { 'Content-MD5' => "e59ff97941044f85df5297e1c302d260",
                    'Content-Type' => "text/plain",
                    'Date' => 5.seconds.ago.utc.httpdate }
        @request_with_nonce = Curl::Easy.new("/resource.xml?foo=bar&bar=foo") do |curl|
          curl.headers = nonce_headers
        end
        @signed_request_with_nonce = ApiAuth.sign!(@request_with_nonce, @access_id, @secret_key, :use_nonce=>true)
      end

      it "should return a Curl::Easy object after signing it" do
        ApiAuth.sign!(@request, @access_id, @secret_key).class.to_s.should match("Curl::Easy")
      end

      describe "md5 header" do
        it "should not calculate and add the content-md5 header if not provided" do
          headers = { 'Content-Type' => "text/plain",
                      'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
          request = Curl::Easy.new("/resource.xml?foo=bar&bar=foo") do |curl|
            curl.headers = headers
          end
          signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
          signed_request.headers['Content-MD5'].should == nil
        end

        it "should leave the content-md5 alone if provided" do
          @signed_request.headers['Content-MD5'].should == "e59ff97941044f85df5297e1c302d260"
        end
      end

      it "should sign the request" do
        @signed_request.headers['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request)}"
      end

      it "should sign the request with a nonce" do
        @signed_request_with_nonce.headers['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request_with_nonce)}&NONCE:#{ApiAuth.generate_nonce(@request_with_nonce, @secret_key)}"
      end

      it "should authenticate a valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key).should be_true
      end

      it "should authenticate a valid request with a nonce" do
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key, :check_nonce=>true).should be_true
      end

      it "should NOT authenticate a non-valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key+'j').should be_false
      end

      it "should NOT authenticate a valid request with an invalid nonce" do
        @signed_request_with_nonce.headers["DATE"] = 1.second.from_now.utc.httpdate
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key).should be_false
      end

      it "should NOT authenticate an expired request" do
        @request.headers['Date'] = 16.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate a custom expired request" do
        @request.headers['Date'] = 5.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key, :ttl=>4.minutes.to_i).should be_false
      end
      
      it "should retrieve the access_id" do
        ApiAuth.access_id(@signed_request).should == "1044"
      end

      it "should retrieve the nonce_value" do
        ApiAuth.nonce_value(@signed_request_with_nonce).should == ApiAuth.generate_nonce(@request_with_nonce,@secret_key)
      end

    end

    describe "with ActionController" do

      before(:each) do
        @request = ActionController::Request.new(
          'PATH_INFO' => '/resource.xml',
          'QUERY_STRING' => 'foo=bar&bar=foo',
          'REQUEST_METHOD' => 'PUT',
          'CONTENT_MD5' => '1B2M2Y8AsgTpgAmY7PhCfg==',
          'CONTENT_TYPE' => 'text/plain',
          'HTTP_DATE' => Time.now.utc.httpdate)
        @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)

        @request_with_nonce = ActionController::Request.new(
          'PATH_INFO' => '/resource.xml',
          'QUERY_STRING' => 'foo=bar&bar=foo',
          'REQUEST_METHOD' => 'PUT',
          'CONTENT_MD5' => '1B2M2Y8AsgTpgAmY7PhCfg==',
          'CONTENT_TYPE' => 'text/plain',
          'HTTP_DATE' => Time.now.utc.httpdate)
        @signed_request_with_nonce = ApiAuth.sign!(@request_with_nonce, @access_id, @secret_key, :use_nonce=>true)        
      end

      it "should return a ActionController::Request object after signing it" do
        ApiAuth.sign!(@request, @access_id, @secret_key).class.to_s.should match("ActionController::Request")
      end

      describe "md5 header" do
        context "not already provided" do
          it "should calculate for empty string" do
            request = ActionController::Request.new(
              'PATH_INFO' => '/resource.xml',
              'QUERY_STRING' => 'foo=bar&bar=foo',
              'REQUEST_METHOD' => 'PUT',
              'CONTENT_TYPE' => 'text/plain',
              'HTTP_DATE' => 'Mon, 23 Jan 1984 03:29:56 GMT')
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.env['Content-MD5'].should == Digest::MD5.base64digest('') => Doesn't work in ruby 1.8.7
            signed_request.env['Content-MD5'].should == Base64.encode64(Digest::MD5.digest('')).strip
          end

          it "should calculate for real content" do
            request = ActionController::Request.new(
              'PATH_INFO' => '/resource.xml',
              'QUERY_STRING' => 'foo=bar&bar=foo',
              'REQUEST_METHOD' => 'PUT',
              'CONTENT_TYPE' => 'text/plain',
              'HTTP_DATE' => 'Mon, 23 Jan 1984 03:29:56 GMT',
              'RAW_POST_DATA' => "hello\nworld")
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.env['Content-MD5'].should == Digest::MD5.base64digest("hello\nworld") => Doesn't work in ruby 1.8.7
            signed_request.env['Content-MD5'].should == Base64.encode64(Digest::MD5.digest("hello\nworld")).strip
          end

        end

        it "should leave the content-md5 alone if provided" do
          @signed_request.env['CONTENT_MD5'].should == '1B2M2Y8AsgTpgAmY7PhCfg=='
        end
      end

      it "should sign the request" do
        @signed_request.env['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request)}"
      end

      it "should sign the request with a nonce" do
        @signed_request_with_nonce.env['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request_with_nonce)}&NONCE:#{ApiAuth.generate_nonce(@request_with_nonce, @secret_key)}"
      end

      it "should authenticate a valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key).should be_true
      end

      it "should authenticate a valid request with a nonce" do
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key, :check_nonce=>true).should be_true
      end

      it "should NOT authenticate a non-valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key+'j').should be_false
      end

      it "should NOT authenticate a valid request with an invalid nonce" do
        @signed_request_with_nonce.env["DATE"] = 1.second.from_now.utc.httpdate
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key).should be_false
      end

      it "should NOT authenticate a mismatched content-md5 when body has changed" do
        request = ActionController::Request.new(
          'PATH_INFO' => '/resource.xml',
          'QUERY_STRING' => 'foo=bar&bar=foo',
          'REQUEST_METHOD' => 'PUT',
          'CONTENT_TYPE' => 'text/plain',
          'HTTP_DATE' => 'Mon, 23 Jan 1984 03:29:56 GMT',
          'rack.input' => StringIO.new("hello\nworld"))
        signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
        signed_request.instance_variable_get("@env")["rack.input"] = StringIO.new("goodbye")
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate an expired request" do
        @request.env['HTTP_DATE'] = 16.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate a custom expired request" do
        @request.env['Date'] = 5.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key, :ttl=>4.minutes.to_i).should be_false
      end

      it "should retrieve the access_id" do
        ApiAuth.access_id(@signed_request).should == "1044"
      end

      it "should retrieve the nonce_value" do
        ApiAuth.nonce_value(@signed_request_with_nonce).should == ApiAuth.generate_nonce(@request_with_nonce,@secret_key)
      end

    end

    describe "with Rack::Request" do

      before(:each) do
        headers = { 'Content-MD5' => "1B2M2Y8AsgTpgAmY7PhCfg==",
                    'Content-Type' => "text/plain",
                    'Date' => Time.now.utc.httpdate }
        @request = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put).merge!(headers))
        @signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)

        @request_with_nonce = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put).merge!(headers))
        @signed_request_with_nonce = ApiAuth.sign!(@request_with_nonce, @access_id, @secret_key, :use_nonce=>true)
      end

      it "should return a Rack::Request object after signing it" do
        ApiAuth.sign!(@request, @access_id, @secret_key).class.to_s.should match("Rack::Request")
      end

      describe "md5 header" do
        context "not already provided" do
          it "should calculate for empty string" do
            headers = { 'Content-Type' => "text/plain",
                        'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
            request = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put).merge!(headers))
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.env['Content-MD5'].should == Digest::MD5.base64digest('') => Doesn't work in ruby 1.8.7
            signed_request.env['Content-MD5'].should == Base64.encode64(Digest::MD5.digest('')).strip
          end

          it "should calculate for real content" do
            headers = { 'Content-Type' => "text/plain",
                        'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
            request = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put, :input => "hellow\nworld").merge!(headers))
            signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
            # signed_request.env['Content-MD5'].should == Digest::MD5.base64digest("hellow\nworld") => Doesn't work in ruby 1.8.7
            signed_request.env['Content-MD5'].should == Base64.encode64(Digest::MD5.digest("hellow\nworld")).strip
          end
        end

        it "should leave the content-md5 alone if provided" do
          @signed_request.env['Content-MD5'].should == "1B2M2Y8AsgTpgAmY7PhCfg=="
        end
      end

      it "should sign the request" do
        @signed_request.env['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request)}"
      end

      it "should sign the request with a nonce" do
        @signed_request_with_nonce.env['Authorization'].should == "APIAuth 1044:#{hmac(@secret_key, @request_with_nonce)}&NONCE:#{ApiAuth.generate_nonce(@request_with_nonce, @secret_key)}"
      end

      it "should authenticate a valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key).should be_true
      end

      it "should authenticate a valid request with a nonce" do
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key, :check_nonce=>true).should be_true
      end

      it "should NOT authenticate a non-valid request" do
        ApiAuth.authentic?(@signed_request, @secret_key+'j').should be_false
      end

      it "should NOT authenticate a valid request with an invalid nonce" do
        @signed_request_with_nonce.env["DATE"] = 1.second.from_now.utc.httpdate
        ApiAuth.authentic?(@signed_request_with_nonce, @secret_key).should be_false
      end

      it "should NOT authenticate a mismatched content-md5 when body has changed" do
        headers = { 'Content-Type' => "text/plain",
                    'Date' => "Mon, 23 Jan 1984 03:29:56 GMT" }
        request = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put, :input => "hellow\nworld").merge!(headers))
        signed_request = ApiAuth.sign!(request, @access_id, @secret_key)
        changed_request = Rack::Request.new(Rack::MockRequest.env_for("/resource.xml?foo=bar&bar=foo", :method => :put, :input => "goodbye").merge!(headers))
        signed_request.env['rack.input'] = changed_request.env['rack.input']
        signed_request.env['CONTENT_LENGTH'] = changed_request.env['CONTENT_LENGTH']
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate an expired request" do
        @request.env['Date'] = 16.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key).should be_false
      end

      it "should NOT authenticate a custom expired request" do
        @request.env['Date'] = 5.minutes.ago.utc.httpdate
        signed_request = ApiAuth.sign!(@request, @access_id, @secret_key)
        ApiAuth.authentic?(signed_request, @secret_key, :ttl=>4.minutes.to_i).should be_false
      end
      
      it "should retrieve the access_id" do
        ApiAuth.access_id(@signed_request).should == "1044"
      end

      it "should retrieve the nonce_value" do
        ApiAuth.nonce_value(@signed_request_with_nonce).should == ApiAuth.generate_nonce(@request_with_nonce,@secret_key)
      end

    end

  end

end
