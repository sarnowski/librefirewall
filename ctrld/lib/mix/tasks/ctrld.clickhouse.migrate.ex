defmodule Mix.Tasks.Ctrld.Clickhouse.Migrate do
  @shortdoc "Apply the telemetry schema to ClickHouse"

  @moduledoc """
  Apply the telemetry schema to ClickHouse.

  The counterpart of `mix ecto.migrate` for the store Ecto does not own. It
  runs the schema's statements, all of which are `IF NOT EXISTS`, so it is
  safe to run on every start and it is what the gate and the development
  server both do.

  It fails the task on an unreachable store rather than reporting success:
  the suite has tests that need this schema, and a gate that shrugged at a
  missing store would report a pass it did not earn.
  """

  use Mix.Task

  alias Ctrld.Telemetry.Store

  @requirements ["app.config"]

  @impl Mix.Task
  def run(_arguments) do
    {:ok, _} = Application.ensure_all_started(:req)

    case Store.migrate() do
      :ok ->
        Mix.shell().info("ctrld: telemetry schema applied")

      {:error, reason} ->
        Mix.raise("ctrld: could not apply the telemetry schema — " <> Store.describe(reason))
    end
  end
end
