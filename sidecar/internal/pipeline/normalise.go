// normalise.go — Stage 2 of the pipeline.
// Produces canonical text for scanning by applying (in order):
//   1. Recursive URL decoding
//   2. Recursive Base64 and hex decoding
//   3. Unicode NFKC normalisation
//   4. Zero-width character stripping
//   5. Leetspeak cleaning
// The canonical text is written back into the RiskContext for the scan stage.
package pipeline
