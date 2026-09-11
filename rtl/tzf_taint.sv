// tzf_taint.sv — GLIFT-class ATTRIBUTE-TAINT observer (audit builds only)
// COMBINATIONAL attribute tagger: {secure-activity, class, region-stamp}.
// No state, no functional fanout (fm_equiv.sv proves stripping changes
// nothing). Measured overhead <= 1% GE-proxy at all sweep points.
module tzf_taint #(
  parameter int REGION_W = 4
)(
  // decision-cone observation (current cycle)
  input  wire               rd_grant,
  input  wire               wr_grant,
  input  wire               act_fire,      // ar_fire | aw_fire
  input  wire               req_ns,        // AxPROT[1] of decided request
  input  wire [REGION_W-1:0] hit_region,
  input  wire               hit_any,
  output wire [5:0]         tnt_status     // {sec_act, ns, stamp[3:0]}
);
  wire sec_act = act_fire && !req_ns;
  assign tnt_status = {sec_act, req_ns, hit_any ? hit_region : {REGION_W{1'b1}}};
endmodule
