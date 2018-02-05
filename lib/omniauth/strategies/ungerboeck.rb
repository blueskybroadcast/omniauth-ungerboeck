require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Ungerboeck < OmniAuth::Strategies::OAuth2
      option :name, 'ungerboeck'

      option :app_options, { app_event_id: nil }

      option :client_options, {
        authorize_url: 'MUST BE SET',
        user_info_url: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        {
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email],
          id: uid,
          member_status: raw_info[:member_status]
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def request_phase
        @slug ||= session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "?redir=" + callback_url + "?slug=#{@slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.access_token = {
          token: request.params['userToken'],
          token_expires: 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        request_log_text = "#{provider_name} Get User Info Request:\nGET #{user_info_url}, params: { userToken: #{Provider::SECURITY_MASK} }"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(user_info_url, params: { userToken: access_token[:token] })
        rescue RestClient::ExceptionWithResponse => e
          error_log_text = "#{provider_name} Get User Info Response Error #{e.message} (code: #{e.response&.code}):\n#{e.response}"
          @app_event.logs.create(level: 'error', text: error_log_text)
          @app_event.fail!
          return {}
        end

        response_log_text = "#{provider_name} Get User Info Response (code: #{response.code}): \n#{response.body}"
        @app_event.logs.create(level: response.code == 200 ? 'info' : 'error', text: response_log_text)

        if response.code == 200
          if !response.body.include?(invalid_user_message)
            if response.force_encoding('UTF-8').include? "\uFEFF"
              clean_response = response.split
              clean_response.shift
              parsed_response = JSON.parse(clean_response[0])
            else
              parsed_response = JSON.parse(response)
            end

            info = {
              first_name: parsed_response['FirstName'],
              last_name: parsed_response['LastName'],
              email: parsed_response['Email'],
              id: parsed_response['MemberID'],
              member_status: parsed_response['ActiveMember']
            }

            @app_event.update(raw_data: {
              user_info: {
                uid: info[:id],
                email: info[:email],
                first_name: info[:first_name],
                last_name: info[:last_name]
              }
            })
            info
          else
            @app_event.fail!
            raise invalid_user_message
          end
        else
          @app_event.fail!
          raise failed_request_message
        end
      end

      private

      def authorize_url
        options.client_options.authorize_url
      end

      def failed_request_message
        'Something went wrong with the network request.'
      end

      def invalid_user_message
        'This user is not logged in or is not a valid user'
      end

      def user_info_url
        options.client_options.user_info_url
      end

      def provider_name
        options.name
      end
    end
  end
end
