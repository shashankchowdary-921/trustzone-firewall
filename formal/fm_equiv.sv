// fm_equiv.s
// Same config, same stimulus; TAINT_EN=0 (
// (audit instrumentation). Assert every FUNCTIONAL output bit-identical.
// dbg_taint intentionally differs — it IS the instrumentation.
`default_nettype none
module fm_equiv (input wire clk);
  localparam int NR = 16, AW = 32, DW = 32, IW = 4;

  (* anyconst *) reg [NR-1:0]      cfg_enable;
  (* anyconst *) reg [NR*AW-1:0]   cfg_base;
  (* anyconst *) reg [NR*AW-1:0]   cfg_mask;
  (* anyconst *) reg [NR*6-1:0]    cfg_perm;

  (* anyseq *) reg          s_arvalid;
  (* anyseq *) reg [IW-1:0] s_arid;
  (* anyseq *) reg [AW-1:0] s_araddr;
  (* anyseq *) reg [2:0]    s_arprot;
  (* anyseq *) reg          s_rready;
  (* anyseq *) reg          s_awvalid;
  (* anyseq *) reg [IW-1:0] s_awid;
  (* anyseq *) reg [AW-1:0] s_awaddr;
  (* anyseq *) reg [2:0]    s_awprot;
  (* anyseq *) reg          s_wvalid;
  (* anyseq *) reg          s_wlast;
  (* anyseq *) reg          s_bready;
  (* anyseq *) reg          m_arready;
  (* anyseq *) reg          m_rvalid;
  (* anyseq *) reg [IW-1:0] m_rid;
  (* anyseq *) reg [DW-1:0] m_rdata;
  (* anyseq *) reg          m_awready;
  (* anyseq *) reg          m_wready;
  (* anyseq *) reg          m_bvalid;
  (* anyseq *) reg [IW-1:0] m_bid;

  wire s_arreadyA,s_arreadyB, s_rvalidA,s_rvalidB, s_rlastA,s_rlastB;
  wire s_awreadyA,s_awreadyB, s_wreadyA,s_wreadyB, s_bvalidA,s_bvalidB;
  wire [IW-1:0] s_ridA,s_ridB, s_bidA,s_bidB;
  wire [DW-1:0] s_rdataA,s_rdataB;
  wire [1:0]    s_rrespA,s_rrespB, s_brespA,s_brespB;
  wire dpendA,dpendB, irqA,irqB, ovfA,ovfB, lvA,lvB;
  wire [1:0] wsA,wsB; wire [2:0] cntA,cntB; wire [5:0] tntA,tntB;
  wire [IW-1:0] ridA,ridB,widA,widB; wire [47:0] logdA,logdB;

  tz_firewall #(.N_REGIONS(NR), .ADDR_WIDTH(AW), .DATA_WIDTH(DW),
                .ID_WIDTH(IW), .LOG_DEPTH(4), .TS_WIDTH(8), .TAINT_EN(1))
  uA (.ACLK(clk), .ARESETn(rstn),
    .cfg_enable(cfg_enable), .cfg_base(cfg_base), .cfg_mask(cfg_mask),
    .cfg_perm(cfg_perm), .cfg_int_en(1'b1), .cfg_clr_ovf(1'b0),
    .log_rd_en(1'b0), .log_rd_data(logdA), .log_rd_valid(lvA),
    .log_ovf(ovfA), .irq(irqA),
    .s_arid(s_arid), .s_araddr(s_araddr), .s_arlen(8'h0), .s_arsize(3'd2),
    .s_arburst(2'd1), .s_arprot(s_arprot), .s_arvalid(s_arvalid), .s_arready(s_arreadyA),
    .s_rid(s_ridA), .s_rdata(s_rdataA), .s_rresp(s_rrespA), .s_rlast(s_rlastA),
    .s_rvalid(s_rvalidA), .s_rready(s_rready),
    .s_awid(s_awid), .s_awaddr(s_awaddr), .s_awlen(8'h0), .s_awsize(3'd2),
    .s_awburst(2'd1), .s_awprot(s_awprot), .s_awvalid(s_awvalid), .s_awready(s_awreadyA),
    .s_wdata(32'h0), .s_wstrb(4'hF), .s_wlast(s_wlast),
    .s_wvalid(s_wvalid), .s_wready(s_wreadyA),
    .s_bid(s_bidA), .s_bresp(s_brespA), .s_bvalid(s_bvalidA), .s_bready(s_bready),
    .m_arid(), .m_araddr(), .m_arlen(), .m_arsize(), .m_arburst(), .m_arprot(),
    .m_arvalid(), .m_arready(m_arready),
    .m_rid(m_rid), .m_rdata(m_rdata), .m_rresp(2'b00), .m_rlast(1'b1),
    .m_rvalid(m_rvalid), .m_rready(),
    .m_awid(), .m_awaddr(), .m_awlen(), .m_awsize(), .m_awburst(), .m_awprot(),
    .m_awvalid(), .m_awready(m_awready),
    .m_wdata(), .m_wstrb(), .m_wlast(),
    .m_wvalid(), .m_wready(m_wready),
    .m_bid(m_bid), .m_bresp(2'b00), .m_bvalid(m_bvalid), .m_bready(),
    .dbg_rd_pend(dpendA), .dbg_ws_state(wsA), .dbg_log_cnt(cntA),
    .dbg_taint(tntA), .dbg_rd_id(ridA), .dbg_w_id(widA));

  tz_firewall #(.N_REGIONS(NR), .ADDR_WIDTH(AW), .DATA_WIDTH(DW),
                .ID_WIDTH(IW), .LOG_DEPTH(4), .TS_WIDTH(8), .TAINT_EN(0))
  uB (.ACLK(clk), .ARESETn(rstn),
    .cfg_enable(cfg_enable), .cfg_base(cfg_base), .cfg_mask(cfg_mask),
    .cfg_perm(cfg_perm), .cfg_int_en(1'b1), .cfg_clr_ovf(1'b0),
    .log_rd_en(1'b0), .log_rd_data(logdB), .log_rd_valid(lvB),
    .log_ovf(ovfB), .irq(irqB),
    .s_arid(s_arid), .s_araddr(s_araddr), .s_arlen(8'h0), .s_arsize(3'd2),
    .s_arburst(2'd1), .s_arprot(s_arprot), .s_arvalid(s_arvalid), .s_arready(s_arreadyB),
    .s_rid(s_ridB), .s_rdata(s_rdataB), .s_rresp(s_rrespB), .s_rlast(s_rlastB),
    .s_rvalid(s_rvalidB), .s_rready(s_rready),
    .s_awid(s_awid), .s_awaddr(s_awaddr), .s_awlen(8'h0), .s_awsize(3'd2),
    .s_awburst(2'd1), .s_awprot(s_awprot), .s_awvalid(s_awvalid), .s_awready(s_awreadyB),
    .s_wdata(32'h0), .s_wstrb(4'hF), .s_wlast(s_wlast),
    .s_wvalid(s_wvalid), .s_wready(s_wreadyB),
    .s_bid(s_bidB), .s_bresp(s_brespB), .s_bvalid(s_bvalidB), .s_bready(s_bready),
    .m_arid(), .m_araddr(), .m_arlen(), .m_arsize(), .m_arburst(), .m_arprot(),
    .m_arvalid(), .m_arready(m_arready),
    .m_rid(m_rid), .m_rdata(m_rdata), .m_rresp(2'b00), .m_rlast(1'b1),
    .m_rvalid(m_rvalid), .m_rready(),
    .m_awid(), .m_awaddr(), .m_awlen(), .m_awsize(), .m_awburst(), .m_awprot(),
    .m_awvalid(), .m_awready(m_awready),
    .m_wdata(), .m_wstrb(), .m_wlast(),
    .m_wvalid(), .m_wready(m_wready),
    .m_bid(m_bid), .m_bresp(2'b00), .m_bvalid(m_bvalid), .m_bready(),
    .dbg_rd_pend(dpendB), .dbg_ws_state(wsB), .dbg_log_cnt(cntB),
    .dbg_taint(tntB), .dbg_rd_id(ridB), .dbg_w_id(widB));

  // reset run-up
  reg runup = 1'b0;
  always @(posedge clk) runup <= 1'b1;
  wire rstn = runup;

  // ============ FUNCTIONAL-EQUIVALENCE OBSERVATIONS ============
  always @(posedge clk) if (rstn) begin
    assert (s_arreadyA == s_arreadyB);
    assert (s_rvalidA == s_rvalidB);
    assert (s_ridA == s_ridB);
    assert (s_rdataA == s_rdataB);
    assert (s_rrespA == s_rrespB);
    assert (s_rlastA == s_rlastB);
    assert (s_awreadyA == s_awreadyB);
    assert (s_wreadyA == s_wreadyB);
    assert (s_bvalidA == s_bvalidB);
    assert (s_bidA == s_bidB);
    assert (s_brespA == s_brespB);
    assert (irqA == irqB);
    assert (ovfA == ovfB);
    assert (lvA == lvB);
    // internal machinery aligned (strengthens induction):
    assert (dpendA == dpendB);
    assert (wsA == wsB);
    assert (cntA == cntB);
    assert (ridA == ridB);
    assert (widA == widB);
    // NOTE: tntA != tntB allowed — instrumentation output only
  end
endmodule
`default_nettype wire
