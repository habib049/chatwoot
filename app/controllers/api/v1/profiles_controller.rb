class Api::V1::ProfilesController < Api::BaseController
  PASSWORD_KEYS = %w[password password_confirmation current_password].freeze
  CREDENTIAL_KEYS = (PASSWORD_KEYS + ['email']).freeze

  before_action :set_user
  before_action :reject_local_credential_changes, only: :update

  def show; end

  def update
    if password_params[:password].present?
      render_could_not_create_error('Invalid current password') and return unless @user.valid_password?(password_params[:current_password])

      @user.update!(password_params.except(:current_password))
    end

    @user.assign_attributes(profile_params)
    @user.custom_attributes.merge!(custom_attributes_params)
    @user.save!
  end

  def avatar
    @user.avatar.attachment.destroy! if @user.avatar.attached?
    @user.reload
  end

  def auto_offline
    @user.account_users.find_by!(account_id: auto_offline_params[:account_id]).update!(auto_offline: auto_offline_params[:auto_offline] || false)
  end

  def availability
    @user.account_users.find_by!(account_id: availability_params[:account_id]).update!(availability: availability_params[:availability])
  end

  def set_active_account
    @user.account_users.find_by(account_id: profile_params[:account_id]).update(active_at: Time.now.utc)
    head :ok
  end

  def resend_confirmation
    @user.send_confirmation_instructions unless @user.confirmed?
    head :ok
  end

  def reset_access_token
    @user.access_token.regenerate_token
    @user.reload
  end

  private

  def set_user
    @user = current_user
  end

  # In SSO mode the email is the SSO lookup key and there is no local password, so the server refuses
  # changes the SPA hides. Wrong-typed values are a 422, never a 500. Keys off SsoMode only, so the
  # DB-backed DISABLE_USER_PROFILE_UPDATE flag cannot open it.
  def reject_local_credential_changes
    return unless SsoMode.enabled? && params.key?(:profile)

    profile = params[:profile]
    return render_sso_error(:unprocessable_entity, 'sso_invalid_param') unless credential_params_valid?(profile)

    render_sso_error(:forbidden, 'sso_local_auth_disabled') if password_change?(profile) || email_change?(profile)
  end

  def credential_params_valid?(profile)
    profile.is_a?(ActionController::Parameters) && CREDENTIAL_KEYS.all? { |key| !profile.key?(key) || profile[key].is_a?(String) }
  end

  def password_change?(profile)
    PASSWORD_KEYS.any? { |key| profile[key].present? }
  end

  def email_change?(profile)
    profile.key?(:email) && profile[:email].strip.downcase != @user.email.to_s.strip.downcase
  end

  def render_sso_error(status, error_code)
    render json: { error: 'Local credential changes are disabled', error_code: error_code }, status: status
  end

  def availability_params
    params.require(:profile).permit(:account_id, :availability)
  end

  def auto_offline_params
    params.require(:profile).permit(:account_id, :auto_offline)
  end

  def profile_params
    params.require(:profile).permit(
      :email,
      :name,
      :display_name,
      :avatar,
      :message_signature,
      :account_id,
      ui_settings: {}
    )
  end

  def custom_attributes_params
    params.require(:profile).permit(:phone_number)
  end

  def password_params
    params.require(:profile).permit(
      :current_password,
      :password,
      :password_confirmation
    )
  end
end
