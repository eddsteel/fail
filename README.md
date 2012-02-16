FAIL
------

FAIL is a small library that provides access to Facebook's API.

Facebook's API functions are directly applicable to the FAIL::Facebook
object, e.g.

		facebook = Facebook.new
		facebook.login(email, pass)
    facebook.friends.get(1)

Will provide the friends of user 1 (if you have permission to do that). The
login step is optional but provides more of the API.


It also provides a FAIL::Profile object, which can be subclassed to provide
easy population of a large number of profiles with only specific information
in them.

Populate the <code>@@fields</code> class variable, and provide a suitable
initialize method, and FAIL will do the rest. e.g.:

    class Profile < FAIL::Profile
      include ParseDate

      @@fields = %w[uid name birthday_date]
      attr_reader :id, :name, :birthday

      def initialize(id, name, birthday_date)
        super(id, name)
        y,m,d = parsedate(birthday_date)[0..2]
        y ||= 2010 
        @birthday = Date.new(y, m, d)
      end

      def self.find_all(fb, uids=fb.get_friends)
        super(fb, uids)
      end
    end

With the above class, a call to Profile.find_all(facebook) with a logged in Facebook
object will return a list of profiles with name and birthday filled out.
