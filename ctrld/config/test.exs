import Config

# The suite owns a whole database and drives it through the sandbox, so every
# test sees the schema and none sees another's rows. `mix test` creates and
# migrates it first (see the alias in mix.exs), because a gate that answered
# "no database, no database tests" would be a gate that passes for the wrong
# reason.
config :ctrld, Ctrld.Repo,
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# The real algorithm at a work factor a suite can afford. 600,000 iterations
# per password would spend the suite's whole budget proving a constant.
config :ctrld, Ctrld.Accounts.Password, iterations: 1_000

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :ctrld, CtrldWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "xwrXhcJTzSu+Nsn9mwZWJSek60LFK1dRGZ0bXqiOFGTg3p0ioSeG/BTzL7RDp8j+",
  server: false

# In test we don't send emails
config :ctrld, Ctrld.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
