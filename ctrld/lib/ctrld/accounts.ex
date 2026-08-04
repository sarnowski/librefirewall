defmodule Ctrld.Accounts do
  @moduledoc """
  Local accounts and their sessions.
  """

  alias Ctrld.Accounts.{Password, User, UserToken}
  alias Ctrld.Repo

  @doc "How many accounts exist."
  def count_users, do: Repo.aggregate(User, :count)

  @doc "One account by its address, already normalised the way the column stores it."
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: email |> String.trim() |> String.downcase())
  end

  @doc "Create an account."
  def create_user(attributes) do
    %User{}
    |> User.changeset(attributes)
    |> Repo.insert()
  end

  @doc """
  The account those credentials belong to, or nil.

  A missing account still spends the work of a real verification, so "no such
  address" and "wrong password" cost the same and the answer does not
  enumerate the account list.
  """
  def get_user_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    case get_user_by_email(email) do
      nil ->
        _ = Password.no_user_verify()
        nil

      user ->
        if Password.verify(password, user.hashed_password), do: user, else: nil
    end
  end

  @doc "Start a session and return the token the cookie carries."
  def create_session_token(%User{} = user) do
    {token, row} = UserToken.build_session_token(user)
    Repo.insert!(row)
    token
  end

  @doc "The account a session token names, or nil once it is gone or expired."
  def get_user_by_session_token(token) when is_binary(token) do
    Repo.one(UserToken.verify_session_token_query(token))
  end

  def get_user_by_session_token(_other), do: nil

  @doc "End a session."
  def delete_session_token(token) when is_binary(token) do
    UserToken.hash(token)
    |> UserToken.by_token_and_context_query(UserToken.session_context())
    |> Repo.delete_all()

    :ok
  end
end
