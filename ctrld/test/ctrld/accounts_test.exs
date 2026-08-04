defmodule Ctrld.AccountsTest do
  # Not async: one test replaces the configured work factor, which every other
  # test that hashes a password reads.
  use Ctrld.DataCase, async: false

  alias Ctrld.Accounts
  alias Ctrld.Accounts.Password

  describe "the password hash" do
    test "verifies the password it was made from" do
      hash = Password.hash("a-long-enough-password")
      assert Password.verify("a-long-enough-password", hash)
    end

    test "refuses any other password" do
      hash = Password.hash("a-long-enough-password")
      refute Password.verify("a-long-enough-passwore", hash)
      refute Password.verify("", hash)
      refute Password.verify("A-LONG-ENOUGH-PASSWORD", hash)
    end

    test "carries its own algorithm and work factor, so neither is an assumption" do
      hash = Password.hash("a-long-enough-password")
      assert ["pbkdf2-sha512", iterations, _salt, _key] = String.split(hash, "$")
      assert String.to_integer(iterations) > 0
    end

    test "two hashes of one password differ, because the salt is fresh each time" do
      refute Password.hash("same-password-twice") == Password.hash("same-password-twice")
    end

    test "verifies a hash made under a different work factor than the one now configured" do
      configured = Application.get_env(:ctrld, Password)
      on_exit(fn -> Application.put_env(:ctrld, Password, configured) end)

      Application.put_env(:ctrld, Password, iterations: 500)
      hash = Password.hash("a-long-enough-password")

      Application.put_env(:ctrld, Password, iterations: 2_000)
      assert Password.verify("a-long-enough-password", hash)
    end

    test "a stored value this module did not write is a refusal rather than a crash" do
      for stored <- [
            "",
            "garbage",
            "pbkdf2-sha512$",
            "pbkdf2-sha512$x$y$z",
            "a$b$c$d",
            "pbkdf2-sha512$0$AAAA$AAAA",
            "pbkdf2-sha512$1000$!!!$AAAA"
          ] do
        refute Password.verify("a-long-enough-password", stored)
      end
    end

    test "a nil hash is a refusal" do
      refute Password.verify("a-long-enough-password", nil)
    end
  end

  describe "creating an account" do
    test "normalises the address so there is one notion of the same account" do
      {:ok, user} =
        Accounts.create_user(%{
          email: "  Admin@Example.Invalid  ",
          password: "a-long-enough-password",
          role: "administrator"
        })

      assert user.email == "admin@example.invalid"
    end

    test "never keeps the password" do
      user = administrator_fixture()
      assert user.password == nil
      refute user.hashed_password == "a-long-enough-password"
      refute String.contains?(user.hashed_password, "a-long-enough-password")
    end

    test "refuses a duplicate address" do
      user = administrator_fixture()

      assert {:error, changeset} =
               Accounts.create_user(%{
                 email: user.email,
                 password: "a-long-enough-password",
                 role: "administrator"
               })

      assert %{email: ["has already been taken"]} = errors_on(changeset)
    end

    test "refuses a short password, an unknown role, and a value that is not an address" do
      assert {:error, short} =
               Accounts.create_user(%{email: "a@b", password: "short", role: "administrator"})

      assert %{password: [_]} = errors_on(short)

      assert {:error, role} =
               Accounts.create_user(%{
                 email: "a@b",
                 password: "a-long-enough-password",
                 role: "root"
               })

      assert %{role: [_]} = errors_on(role)

      assert {:error, address} =
               Accounts.create_user(%{
                 email: "not an address",
                 password: "a-long-enough-password",
                 role: "administrator"
               })

      assert %{email: [_]} = errors_on(address)
    end
  end

  describe "signing in" do
    test "returns the account for the right credentials" do
      user = administrator_fixture()

      assert %{id: id} =
               Accounts.get_user_by_email_and_password(user.email, "a-long-enough-password")

      assert id == user.id
    end

    test "matches the address case-insensitively, as the column stores it" do
      user = administrator_fixture()

      assert Accounts.get_user_by_email_and_password(
               String.upcase(user.email),
               "a-long-enough-password"
             )
    end

    test "returns nothing for a wrong password" do
      user = administrator_fixture()
      refute Accounts.get_user_by_email_and_password(user.email, "the-wrong-password")
    end

    test "returns nothing for an address that has no account" do
      refute Accounts.get_user_by_email_and_password("nobody@example.invalid", "whatever-long")
    end
  end

  describe "sessions" do
    test "a token names its account" do
      user = administrator_fixture()
      token = Accounts.create_session_token(user)
      assert Accounts.get_user_by_session_token(token).id == user.id
    end

    test "the raw token is not what is stored" do
      user = administrator_fixture()
      token = Accounts.create_session_token(user)
      stored = Repo.one(Ctrld.Accounts.UserToken)
      refute stored.hashed_token == token
      assert stored.hashed_token == :crypto.hash(:sha256, token)
    end

    test "signing out ends the session on the server" do
      user = administrator_fixture()
      token = Accounts.create_session_token(user)
      assert :ok = Accounts.delete_session_token(token)
      refute Accounts.get_user_by_session_token(token)
    end

    test "a token nobody issued names nobody" do
      refute Accounts.get_user_by_session_token(:crypto.strong_rand_bytes(32))
      refute Accounts.get_user_by_session_token("")
      refute Accounts.get_user_by_session_token(:not_a_token)
    end
  end
end
