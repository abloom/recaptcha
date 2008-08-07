# ReCAPTCHA
module Ambethia
  module ReCaptcha
    RECAPTCHA_API_SERVER        = 'http://api.recaptcha.net';
    RECAPTCHA_API_SECURE_SERVER = 'https://api-secure.recaptcha.net';
    RECAPTCHA_VERIFY_SERVER     = 'http://api-verify.recaptcha.net/verify';

    SKIP_VERIFY_ENV = ['test']

    mattr_accessor :public_key, :private_key

    module Helper 
      # Your public API can be specified in the +options+ hash or preferably the environment
      # variable +RECAPTCHA_PUBLIC_KEY+.
      def recaptcha_tags(options = {})
        # Default options
        key   = (options[:public_key] || Ambethia::Recaptcha.public_key)
        raise ReCaptchaError, "No public key specified." unless key
        error = (options[:error] || session[:recaptcha_error])
        uri   = (options[:ssl] ? RECAPTCHA_API_SECURE_SERVER : RECAPTCHA_API_SERVER)
        xhtml = Builder::XmlMarkup.new(:target => out=(''), :indent => 2) # Because I can.

        if options[:display] 
          xhtml.script(:type => "text/javascript"){ xhtml.text! "var RecaptchaOptions = #{options[:display].to_json};\n"}
        end
        
        if options[:ajax]
         xhtml.div(:id => 'dynamic_recaptcha') {}
         xhtml.script(:type => "text/javascript", :src => "#{uri}/js/recaptcha_ajax.js") {}
         xhtml.script(:type => "text/javascript") do
           xhtml.text! "Recaptcha.create('#{key}', document.getElementById('dynamic_recaptcha') );"
         end
        else
          xhtml.script(:type => "text/javascript", :src => "#{uri}/challenge?k=#{key}&error=#{error}") {}
          unless options[:noscript] == false
            xhtml.noscript do
              xhtml.iframe(:src => "#{uri}/noscript?k=#{key}",
                           :height => options[:iframe_height] ||= 300,
                           :width  => options[:iframe_width]  ||= 500,
                           :frameborder => 0) {}; xhtml.br
              xhtml.textarea(:name => "recaptcha_challenge_field", :rows => 3, :cols => 40) {}
              xhtml.input :name => "recaptcha_response_field",
                          :type => "hidden", :value => "manual_challenge"
            end
          end
        end
        
        return out
      end # recaptcha_tags
    end # Helpers
    
    module Controller
      # Your private API key must be specified in the environment variable +RECAPTCHA_PRIVATE_KEY+
      def verify_recaptcha(model = nil, options = {})
        return true if SKIP_VERIFY_ENV.include? ENV['RAILS_ENV']
        
        key = (options[:private_key] || Ambethia::Recaptcha.private_key)
        raise ReCaptchaError, "No private key specified." unless key
        
        begin
          logger.info "Calling reCAPTCHA: #{RECAPTCHA_VERIFY_SERVER}"
          recaptcha = Net::HTTP.post_form(URI.parse(RECAPTCHA_VERIFY_SERVER), {
            :privatekey => key,
            :remoteip   => request.remote_ip,
            :challenge  => params[:recaptcha_challenge_field],
            :response   => params[:recaptcha_response_field]
          })
          answer, error = recaptcha.body.split.map { |s| s.chomp }
          logger.info "reCAPTCHA returned: #{answer.inspect}, #{error.inspect}"
          unless answer == 'true'
            session[:recaptcha_error] = error
            model.valid? if model
            model.errors.add_to_base "Captcha response is incorrect, please try again." if model
            return false
          else
            session[:recaptcha_error] = nil
            return true
          end
        rescue Exception => e
          raise ReCaptchaError, e
        end    
      end # verify_recaptcha
    end # ControllerHelpers

    class ReCaptchaError < StandardError; end
    
  end # ReCaptcha
end # Ambethia