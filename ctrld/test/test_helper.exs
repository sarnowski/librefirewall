alias Ctrld.Telemetry.Store

# The gate hands this suite two real databases and expects a verdict. A
# database that is not there must therefore stop the run rather than turn its
# tests into ones that quietly did not happen — the failure mode a gate cannot
# afford is the one that still prints "0 failures".
unless Store.ready?() do
  raise """
  ctrld: the telemetry store did not answer, so the tests that need it would be \
  reporting on nothing. Run the suite through `make ctrld-test`, which brings \
  ClickHouse up on the gate's internal network.
  """
end

case Ecto.Adapters.SQL.query(Ctrld.Repo, "SELECT 1", []) do
  {:ok, _result} ->
    :ok

  {:error, reason} ->
    raise "ctrld: Postgres did not answer (#{inspect(reason)}); run the suite through `make ctrld-test`"
end

# An exclusion is how a suite silently shrinks. There is no tag in this project
# worth skipping, so any exclusion at all is a configuration mistake and is
# refused here rather than discovered by someone counting tests later.
configured_exclusions = ExUnit.configuration() |> Keyword.get(:exclude, []) |> List.wrap()

unless configured_exclusions == [] do
  raise "ctrld: the suite is configured to exclude #{inspect(configured_exclusions)}; " <>
          "the gate runs every test it has"
end

ExUnit.start()
Ecto.Adapters.SQL.Sandbox.mode(Ctrld.Repo, :manual)
