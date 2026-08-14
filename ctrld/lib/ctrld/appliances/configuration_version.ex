defmodule Ctrld.Appliances.ConfigurationVersion do
  @moduledoc """
  One version of one appliance's configuration document, and how far it got.

  Generations are the appliance's own numbering and start at one, which is the
  document the onboarding package carried. Every later generation travels the
  management channel as a stepped transaction, and the four instants on this row
  are that transaction's history: `staged_at` and `committed_at` are what this
  server sent, `validated_at` and `validation_result` are the appliance's one
  answer, and `confirmed_at` is the send that made a provisional commit
  permanent.

  ## The state is derived, never stored

  `state/1` reads the lifecycle off those instants, on the same reasoning the
  inventory derives an appliance's status: a stored state is a value that can
  disagree with the facts under it, and what an operator needs from a
  configuration history above all else is to be able to believe it.

  ## What is not here, and why

  There is no rollback instant. An unconfirmed commit is undone by the
  appliance's own deadline — over no frame this server sends, and with none
  coming back — so a rollback is not a fact this server holds. A version that was
  committed and never confirmed says exactly that, which is the honest answer.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Ctrld.Channel.Frame

  schema "configuration_versions" do
    field(:generation, :integer)
    field(:document, :string)
    field(:document_sha256, :string)
    field(:staged_at, :utc_datetime)
    field(:validated_at, :utc_datetime)
    field(:validation_result, :string)
    field(:committed_at, :utc_datetime)
    field(:confirmed_at, :utc_datetime)

    belongs_to(:appliance, Ctrld.Appliances.Appliance)
    belongs_to(:author, Ctrld.Accounts.User)

    timestamps(type: :utc_datetime)
  end

  @typedoc """
  One row of this table. Named because the derived state below is specified
  against it, and a spec in the module that defines a schema has to be.
  """
  @type t :: %__MODULE__{}

  @typedoc """
  How far one version got, derived from the instants on its row.

  `:delivered` is the generation an onboarding package carried: it never
  travelled the channel, so none of the four instants is set and it is running on
  the appliance because the appliance booted with it.

  `:staging` is a document this server has sent and the appliance has not yet
  answered for. `:refused` is one the appliance's validator would not have.
  `:staged` is one it accepted as the candidate and that nothing has committed.
  `:committed` is a provisional commit awaiting its confirmation over the next
  connection, which is the one state the appliance will undo on its own.
  `:confirmed` is permanent.
  """
  @type state :: :delivered | :staging | :refused | :staged | :committed | :confirmed

  @doc "The digest a document is recorded under, as 64 lowercase hexadecimal characters."
  @spec digest(binary()) :: String.t()
  def digest(document) when is_binary(document) do
    :sha256 |> :crypto.hash(document) |> Base.encode16(case: :lower)
  end

  @doc """
  How far this version got.

  Read newest fact first, so a version is described by the last thing that
  happened to it rather than by the first.
  """
  @spec state(t()) :: state()
  def state(%__MODULE__{confirmed_at: %DateTime{}}), do: :confirmed
  def state(%__MODULE__{committed_at: %DateTime{}}), do: :committed

  def state(%__MODULE__{validated_at: %DateTime{}, validation_result: line}) do
    if accepted?(line), do: :staged, else: :refused
  end

  def state(%__MODULE__{staged_at: %DateTime{}}), do: :staging
  def state(%__MODULE__{}), do: :delivered

  @doc """
  Whether a result line says the appliance took the document as its candidate.

  The line is the appliance's own field vocabulary and the outcome token is the
  whole of what is read here: a token this server does not know is *not* an
  acceptance, so a build of the appliance that grew a new outcome leaves a
  version un-committed rather than committing on a verdict this end misread.
  """
  @spec accepted?(String.t() | nil) :: boolean()
  def accepted?(line) when is_binary(line), do: outcome(line) == "staged"
  def accepted?(nil), do: false

  @doc """
  The outcome token a result line carries, or nothing where it carries none.

  The line arrives from a semi-trusted appliance, so it is split rather than
  parsed and no part of it becomes an atom.
  """
  @spec outcome(String.t()) :: String.t() | nil
  def outcome(line) when is_binary(line) do
    line
    |> String.split(" ", trim: true)
    |> Enum.find_value(fn field ->
      case String.split(field, "=", parts: 2) do
        ["outcome", token] -> token
        _other -> nil
      end
    end)
  end

  @doc """
  The generation a result line names, or nothing.

  Read back rather than assumed, because the generation the appliance staged
  under is the generation a commit must name: this server chose the next number
  it believed in, and the appliance's own datastore is the authority on what that
  number actually is.
  """
  @spec stated_generation(String.t()) :: pos_integer() | nil
  def stated_generation(line) when is_binary(line) do
    line
    |> String.split(" ", trim: true)
    |> Enum.find_value(fn field ->
      with ["generation", digits] <- String.split(field, "=", parts: 2),
           {generation, ""} when generation > 0 <- Integer.parse(digits) do
        generation
      else
        _not_a_generation -> nil
      end
    end)
  end

  @doc false
  def changeset(version, attributes) do
    version
    |> cast(attributes, [
      :appliance_id,
      :generation,
      :document,
      :document_sha256,
      :author_id,
      :staged_at,
      :validated_at,
      :validation_result,
      :committed_at,
      :confirmed_at
    ])
    |> validate_required([:generation, :document, :document_sha256])
    |> validate_number(:generation, greater_than: 0)
    # The result line is the appliance's, so it is held to the frame's own bound
    # rather than to the column's width: a peer that sent a longer one would
    # otherwise reach a database error instead of a refusal.
    |> validate_length(:validation_result, max: Frame.max_payload_length())
    |> unique_constraint([:appliance_id, :generation])
  end
end
