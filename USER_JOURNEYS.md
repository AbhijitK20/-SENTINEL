# User Journeys

## Analyse A Prepared Replay

1. Analyst selects a deterministic scenario.
2. System validates the data and reports available flow and packet features.
3. Replay advances through time windows.
4. Analyst sees observed state and forecast state separately.
5. Analyst opens a forecast to see stage, affected entities, and evidence.
6. Analyst compares the forecast with the actual next stage.
7. Analyst exports a report.

## Analyse A CSV

1. User uploads a supported flow CSV.
2. System validates required columns and reports unavailable packet features.
3. User chooses a prepared compatible model/configuration.
4. System builds windows and displays the forecast with data-coverage warnings.

## Analyse A PCAP

1. User uploads a PCAP.
2. System parses packets and derives packet-level and flow-derived features.
3. System displays extraction statistics and parsing warnings.
4. User runs inference and reviews the forecast and explanations.

## Review Model Quality

1. Evaluator opens benchmark results.
2. Evaluator sees split strategy and dataset version.
3. Evaluator compares logistic regression with the temporal model.
4. Evaluator reviews precision, recall, F1, false-positive rate, and lead time.
