# Users without email: internally "john" is stored as "john@usuarios.local" and
# the API returns only "john". Logins containing "@" are used as they are, so
# existing accounts and SSO links keep working.
module UsernameLogin
  DOMAIN = 'usuarios.local'.freeze
  FORMAT = /\A[a-z0-9._-]+\z/

  def self.normalize(login)
    login.to_s.strip.downcase
  end

  def self.to_email(login)
    value = login.to_s.strip
    value.include?('@') ? value : "#{value}@#{DOMAIN}"
  end

  def self.to_login(email)
    email.to_s.delete_suffix("@#{DOMAIN}")
  end

  module SessionsPatch
    private

    # This is the first before_action of create, so every later step (SSO,
    # MFA, password) already receives the full email.
    def merge_credential_headers
      super
      params[:email] = UsernameLogin.to_email(params[:email]) if params[:email].present?
    end
  end

  module AgentsPatch
    # The user is created before AgentBuilder runs, already confirmed and with
    # the password from the form, so the builder only links it to the account
    # and sends no email.
    def create
      login = UsernameLogin.normalize(params.dig(:agent, :email))
      return username_error(I18n.t('username_login.invalid_username')) unless login.match?(UsernameLogin::FORMAT)

      email = UsernameLogin.to_email(login)
      return username_error(I18n.t('username_login.username_taken')) if User.from_email(email)

      password = params.dig(:agent, :password).to_s
      user = User.new(name: params.dig(:agent, :name), email: email, password: password, password_confirmation: password)
      user.skip_confirmation!
      return username_error(I18n.t('username_login.weak_password')) if user.invalid? && user.errors[:password].any?

      params[:agent][:email] = email

      User.transaction do
        user.save!
        super
        raise ActiveRecord::Rollback if @agent.nil?
      end
    end

    def update
      login = UsernameLogin.normalize(params.dig(:agent, :email))
      password = params.dig(:agent, :password).presence
      rename = login.present? && login != UsernameLogin.to_login(@agent.email)
      return super unless rename || password

      return username_error(I18n.t('username_login.credentials_protected'), :forbidden) if credentials_protected?(@agent)
      return username_error(I18n.t('username_login.invalid_username')) if rename && !login.match?(UsernameLogin::FORMAT)

      User.transaction do
        if rename
          @agent.email = UsernameLogin.to_email(login)
          @agent.skip_reconfirmation!
        end
        if password
          @agent.password = password
          @agent.password_confirmation = password
          @agent.tokens = {} # sign out sessions opened with the old password
        end
        @agent.save!
        super
      end
    end

    private

    # Keeps an administrator from taking over a super admin, their own account
    # without the current password, or a user who also belongs to another account.
    def credentials_protected?(agent)
      agent.is_a?(SuperAdmin) || agent.id == current_user.id ||
        agent.account_users.where.not(account_id: Current.account.id).exists?
    end

    def username_error(message, status = :unprocessable_entity)
      render json: { message: message }, status: status
    end
  end

  module ProfilesPatch
    def update
      login = UsernameLogin.normalize(params.dig(:profile, :email))
      if login == UsernameLogin.to_login(@user.email)
        params[:profile].delete(:email)
      elsif login.present?
        return render_could_not_create_error(I18n.t('username_login.invalid_username')) unless login.match?(UsernameLogin::FORMAT)

        params[:profile][:email] = UsernameLogin.to_email(login)
        @user.skip_reconfirmation!
      end
      super
    end
  end
end

Rails.application.config.to_prepare do
  DeviseOverrides::SessionsController.prepend(UsernameLogin::SessionsPatch)
  Api::V1::Accounts::AgentsController.prepend(UsernameLogin::AgentsPatch)
  Api::V1::ProfilesController.prepend(UsernameLogin::ProfilesPatch)
end
