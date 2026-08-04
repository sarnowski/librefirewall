defmodule Ctrld.Accounts.UserToken do
  @moduledoc """
  A session token.

  The cookie carries a random token; the database stores its SHA-256 digest.
  A read of the sessions table therefore hands out no live session, and
  signing out deletes the row rather than merely dropping the cookie — a
  session ends where the server can see it end.
  """

  use Ecto.Schema

  import Ecto.Query

  @token_bytes 32
  @session_context "session"
  @session_validity_days 14

  schema "user_tokens" do
    field(:hashed_token, :binary)
    field(:context, :string)
    belongs_to(:user, Ctrld.Accounts.User)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc "A fresh session token and the row that will recognise it."
  def build_session_token(user) do
    token = :crypto.strong_rand_bytes(@token_bytes)

    {token,
     %__MODULE__{
       hashed_token: :crypto.hash(:sha256, token),
       context: @session_context,
       user_id: user.id
     }}
  end

  @doc "The query resolving a session token to its still-valid account."
  def verify_session_token_query(token) when is_binary(token) do
    from(token_row in by_token_and_context_query(:crypto.hash(:sha256, token), @session_context),
      join: user in assoc(token_row, :user),
      where: token_row.inserted_at > ago(@session_validity_days, "day"),
      select: user
    )
  end

  @doc "The query selecting one session row, for deleting it."
  def by_token_and_context_query(hashed_token, context) do
    from(__MODULE__, where: [hashed_token: ^hashed_token, context: ^context])
  end

  @doc "The digest a raw token is stored under."
  def hash(token) when is_binary(token), do: :crypto.hash(:sha256, token)

  @doc "The context every session row carries."
  def session_context, do: @session_context
end
