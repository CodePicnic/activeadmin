ActiveAdmin::Dependency.devise! ActiveAdmin::Dependency::Requirements::DEVISE

require 'devise'

module Devise
  module Models
    module Authenticatable
      module ClassMethods
        # Find or initialize a record with group of attributes based on a list of required attributes.
        def find_or_initialize_without_errors(required_attributes, attributes) #:nodoc:
          attributes = if attributes.respond_to? :permit!
            attributes.slice(*required_attributes).permit!.to_h.with_indifferent_access
          else
            attributes.with_indifferent_access.slice(*required_attributes)
          end
          attributes.delete_if { |key, value| value.blank? }

          if attributes.size == required_attributes.size
            record = find_first_by_auth_conditions(attributes)
          end

          unless record
            record = new

            required_attributes.each do |key|
              value = attributes[key]
              record.send("#{key}=", value)
            end
          end

          record
        end
      end
    end

    module Recoverable
      module ClassMethods
        # Attempt to find a user by its email. If a record is found, send new
        # password instructions to it. If user is not found, won't return a message
        # Attributes must contain the user's email
        def send_reset_password_instructions(attributes={})
          recoverable = find_or_initialize_without_errors(reset_password_keys, attributes)
          recoverable.send_reset_password_instructions if recoverable.persisted?
          recoverable
        end
      end
    end
  end
end

module ActiveAdmin
  module Devise

    def self.config
      {
        path: ActiveAdmin.application.default_namespace || "/",
        controllers: ActiveAdmin::Devise.controllers,
        path_names: { sign_in: 'login', sign_out: "logout" },
        sign_out_via: [*::Devise.sign_out_via, ActiveAdmin.application.logout_link_method].uniq
      }
    end

    def self.controllers
      {
        sessions: "active_admin/devise/sessions",
        passwords: "active_admin/devise/passwords",
        unlocks: "active_admin/devise/unlocks",
        registrations: "active_admin/devise/registrations",
        confirmations: "active_admin/devise/confirmations"
      }
    end

    module Controller
      extend ::ActiveSupport::Concern
      included do
        layout 'active_admin_logged_out'
        helper ::ActiveAdmin::ViewHelpers
      end

      # Redirect to the default namespace on logout
      def root_path
        namespace = ActiveAdmin.application.default_namespace.presence
        root_path_method = [namespace, :root_path].compact.join('_')

        path = if Helpers::Routes.respond_to? root_path_method
                 Helpers::Routes.send root_path_method
               else
                 # Guess a root_path when url_helpers not helpful
                 "/#{namespace}"
               end

        # NOTE: `relative_url_root` is deprecated by rails.
        #       Remove prefix here if it is removed completely.
        prefix = Rails.configuration.action_controller[:relative_url_root] || ''
        prefix + path
      end
    end

    class SessionsController < ::Devise::SessionsController
      include ::ActiveAdmin::Devise::Controller
    end

    class PasswordsController < ::Devise::PasswordsController
      include ::ActiveAdmin::Devise::Controller
    end

    class UnlocksController < ::Devise::UnlocksController
      include ::ActiveAdmin::Devise::Controller
    end

    class RegistrationsController < ::Devise::RegistrationsController
       include ::ActiveAdmin::Devise::Controller
    end

    class ConfirmationsController < ::Devise::ConfirmationsController
       include ::ActiveAdmin::Devise::Controller
    end

    def self.controllers_for_filters
      [SessionsController, PasswordsController, UnlocksController,
        RegistrationsController, ConfirmationsController
      ]
    end

  end
end
