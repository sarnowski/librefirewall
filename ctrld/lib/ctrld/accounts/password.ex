defmodule Ctrld.Accounts.Password do
  @moduledoc """
  Password hashing for the server's local accounts.

  PBKDF2-HMAC-SHA512 from Erlang's `:crypto`. It is a proven construction that
  ships with the runtime, which is why it is preferred here to a hashing
  library carrying a native extension: the server implements no cryptographic
  algorithm, and this way it also links none.

  A stored hash is self-describing — `pbkdf2-sha512$<iterations>$<salt>$<key>`
  — so the work factor is a field of the record rather than an assumption of
  the code, and raising it later re-hashes on next sign-in instead of
  invalidating every password at once.
  """

  @digest :sha512
  @salt_bytes 16
  @derived_bytes 64
  @prefix "pbkdf2-sha512"

  @doc "Hash a password under the configured work factor."
  @spec hash(String.t()) :: String.t()
  def hash(password) when is_binary(password) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)
    iterations = iterations()
    derived = :crypto.pbkdf2_hmac(@digest, password, salt, iterations, @derived_bytes)

    Enum.join(
      [@prefix, Integer.to_string(iterations), Base.encode64(salt), Base.encode64(derived)],
      "$"
    )
  end

  @doc """
  Whether `password` produced `stored`, compared in constant time.

  A stored value this module did not write is a `false`, not a crash: it is
  read out of a database row, and a row that has been tampered with must fail
  the sign-in rather than the process.
  """
  @spec verify(String.t(), String.t() | nil) :: boolean()
  def verify(password, stored) when is_binary(password) and is_binary(stored) do
    with [@prefix, iterations, salt, derived] <- String.split(stored, "$"),
         {iterations, ""} when iterations > 0 <- Integer.parse(iterations),
         {:ok, salt} <- Base.decode64(salt),
         {:ok, derived} <- Base.decode64(derived) do
      :crypto.hash_equals(
        derived,
        :crypto.pbkdf2_hmac(@digest, password, salt, iterations, byte_size(derived))
      )
    else
      _ -> false
    end
  end

  def verify(password, nil) when is_binary(password) do
    _ = no_user_verify()
    false
  end

  @doc """
  Spend the same work as a real verification against no user at all.

  Without it, "no such account" answers faster than "wrong password", and the
  difference enumerates the account list.
  """
  @spec no_user_verify() :: false
  def no_user_verify do
    _ =
      :crypto.pbkdf2_hmac(
        @digest,
        "",
        :crypto.strong_rand_bytes(@salt_bytes),
        iterations(),
        @derived_bytes
      )

    false
  end

  defp iterations, do: Application.fetch_env!(:ctrld, __MODULE__)[:iterations]
end
