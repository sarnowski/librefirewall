defmodule Ctrld.DataCase do
  @moduledoc """
  The case template for tests that touch Postgres.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Ctrld.DataCase
      import Ctrld.Fixtures

      alias Ctrld.Repo
    end
  end

  setup tags do
    Ctrld.DataCase.setup_sandbox(tags)
    :ok
  end

  @doc "Check a connection out of the sandbox for this test."
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Ctrld.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  @doc "The messages a changeset carries, as a map from field to reasons."
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, options} ->
      Regex.replace(~r"%{(\w+)}", message, fn _whole, key ->
        options |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
