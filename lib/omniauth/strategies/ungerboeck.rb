require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Ungerboeck < OmniAuth::Strategies::OAuth2
      option :name, 'ungerboeck'

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
        { :raw_info => raw_info }
      end

      def request_phase
        @slug ||= session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "?redir=" + callback_url + "?slug=#{@slug}"
      end

      def callback_phase
        self.access_token = {
          :token =>  request.params['userToken'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        response = RestClient.get(user_info_url, params: { userToken: access_token[:token] })

        if response.code == 200
          if !response.body.include?(invalid_user_message)
            if response.force_encoding("UTF-8").include? "\uFEFF"
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
          else
            raise invalid_user_message
          end
        else
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
    end
  end
end
