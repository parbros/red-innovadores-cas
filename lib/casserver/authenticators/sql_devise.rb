require 'casserver/authenticators/sql'

require 'bcrypt'

# Essentially the same as the standard SQL authenticator but assumes that
# BCrypt has been used to encrypt the password. If you're using
# has_secure_password, then this is probably for you.
class CASServer::Authenticators::SQLDevise < CASServer::Authenticators::SQL

  def validate(credentials)    
    read_standard_credentials(credentials)
    raise_if_not_configured

    user_model = self.class.user_model

    username_column = @options[:username_column] || "username"
    password_column = @options[:password_column] || "encrypted_password"

    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    
    puts "#{username_column} = #{@username}"

    if results.size > 0
      user = results.first

      bcrypt   = ::BCrypt::Password.new(user.encrypted_password)
      password = ::BCrypt::Engine.hash_secret("#{@password}", bcrypt.salt)

      puts password
      puts user.encrypted_password

      return secure_compare(password, user.encrypted_password)
    else
      false
    end

    false
  end

  protected

  def secure_compare(a, b)
    return false if a.blank? || b.blank? || a.bytesize != b.bytesize
    l = a.unpack "C#{a.bytesize}"

    res = 0
    b.each_byte { |byte| res |= byte ^ l.shift }
    res == 0
  end
  

end