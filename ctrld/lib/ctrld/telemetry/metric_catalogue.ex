defmodule Ctrld.Telemetry.MetricCatalogue do
  @moduledoc """
  What every slot of a metric snapshot means.

  A snapshot is a few hundred bare unsigned integers, and which series each one
  is comes from the appliance's own catalogue: a slot's position in the table
  *is* its identity. This module is that table, generated from the appliance's
  `lfw_metrics` into `priv/metric_catalogue.json` and read in at compile time,
  so there is one copy of it in the repository rather than one per language. The
  appliance's build gate regenerates it and refuses a tree where the two have
  parted.

  ## The fingerprint is what makes a stale table safe

  Every snapshot carries a fingerprint derived from every family name, label and
  shard of the table it was written against. This server compares it before
  mapping a single slot, and a snapshot from another catalogue is refused
  whole — no rows at all — rather than mapped through this one. A wrong number
  under the right name is worse than a missing number, because nothing
  downstream can tell it from a measurement; a refusal is visible in the ingest
  counters and in the log.

  So an appliance ahead of this server loses its metric rows until the server
  catches up, and it never writes a misattributed one. That is the intended
  trade.
  """

  @external_resource Path.join(:code.priv_dir(:ctrld), "metric_catalogue.json")

  @catalogue @external_resource |> File.read!() |> Jason.decode!()

  @fingerprint Map.fetch!(@catalogue, "fingerprint")
  @slots Map.fetch!(@catalogue, "slots")

  # One tuple per slot, in the snapshot's own order, so mapping a snapshot is a
  # zip rather than a lookup per value. Built at compile time because the file is
  # read then: nothing at run time reads it, and nothing can arrive that would
  # change it.
  @series @catalogue
          |> Map.fetch!("series")
          |> Enum.map(fn entry ->
            {Map.fetch!(entry, "family"),
             entry |> Map.fetch!("labels") |> Map.put("domain", Map.fetch!(entry, "domain"))}
          end)

  # The generated file is positional, and a length that disagrees with its own
  # stated slot count would silently shift every series after the disagreement
  # onto another one's numbers. Checked here, at compile time, because there is
  # no later moment at which it could be checked usefully.
  if length(@series) != @slots do
    raise "metric_catalogue.json states #{@slots} slots and carries #{length(@series)} series"
  end

  @doc "The catalogue fingerprint this build maps snapshots through."
  @spec fingerprint() :: non_neg_integer()
  def fingerprint, do: @fingerprint

  @doc "How many slots a snapshot this build can map carries."
  @spec slots() :: non_neg_integer()
  def slots, do: @slots

  @doc """
  Every slot's family and labels, in the snapshot's own order.

  The labels already carry `domain`, which is the shard's, so a caller writes
  the map it is given without composing anything.
  """
  @spec series() :: [{String.t(), %{String.t() => String.t()}}]
  def series, do: @series
end
