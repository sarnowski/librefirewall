# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :ctrld,
  ecto_repos: [Ctrld.Repo],
  generators: [timestamp_type: :utc_datetime]

# The password hash's work factor. It is configuration rather than a constant
# because the test environment cannot afford the real one and must still
# exercise the real algorithm; every stored hash carries the count it was
# derived under, so lowering or raising this never invalidates an existing
# password.
config :ctrld, Ctrld.Accounts.Password, iterations: 600_000

# The name the management certificate authority is created under on first
# start. It is the CA's subject common name and nothing else depends on it.
config :ctrld, Ctrld.PKI, authority_name: "librefirewall management CA"

# Configure the endpoint
config :ctrld, CtrldWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: CtrldWeb.ErrorHTML, json: CtrldWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Ctrld.PubSub,
  live_view: [signing_salt: "4Dwpm2yM"]

# Configure LiveView
config :phoenix_live_view,
  # the attribute set on all root tags. Used for Phoenix.LiveView.ColocatedCSS.
  root_tag_attribute: "phx-r"

# Configure the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :ctrld, Ctrld.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  ctrld: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.3.0",
  ctrld: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
