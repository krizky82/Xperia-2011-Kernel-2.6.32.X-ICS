/* Copyright (c) 2009-2010, Code Aurora Forum. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of Code Aurora Forum, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef MDP4_H
#define MDP4_H

extern struct mdp_dma_data dma2_data;
extern struct mdp_dma_data dma_s_data;
extern struct mdp_dma_data dma_e_data;
extern struct mdp_histogram mdp_hist;
extern struct completion mdp_hist_comp;
extern boolean mdp_is_in_isr;
extern uint32 mdp_intr_mask;
extern spinlock_t mdp_spin_lock;
extern struct mdp4_statistic mdp4_stat;
extern uint32 mdp4_extn_disp;

#define MDP4_OVERLAYPROC0_BASE	0x10000
#define MDP4_OVERLAYPROC1_BASE	0x18000

#define MDP4_VIDEO_BASE 0x20000
#define MDP4_VIDEO_OFF 0x10000

#define MDP4_RGB_BASE 0x40000
#define MDP4_RGB_OFF 0x10000

enum {		/* display */
	PRIMARY_INTF_SEL,
	SECONDARY_INTF_SEL,
	EXTERNAL_INTF_SEL
};

enum {
	LCDC_RGB_INTF,			/* 0 */
	DTV_INTF = LCDC_RGB_INTF,	/* 0 */
	MDDI_LCDC_INTF,			/* 1 */
	MDDI_INTF,			/* 2 */
	EBI2_INTF,			/* 3 */
	TV_INTF = EBI2_INTF,		/* 3 */
	DSI_VIDEO_INTF,
	DSI_CMD_INTF
};

enum {
	MDDI_PRIMARY_SET,
	MDDI_SECONDARY_SET,
	MDDI_EXTERNAL_SET
};

enum {
	EBI2_LCD0,
	EBI2_LCD1
};

#define MDP4_PANEL_MDDI         BIT(0)
#define MDP4_PANEL_LCDC         BIT(1)
#define MDP4_PANEL_DTV          BIT(2)
#define MDP4_PANEL_ATV          BIT(3)
#define MDP4_PANEL_DSI_VIDEO    BIT(4)
#define MDP4_PANEL_DSI_CMD      BIT(5)

enum {
	OVERLAY_MODE_NONE,
	OVERLAY_MODE_BLT
};

enum {
	OVERLAY_REFRESH_ON_DEMAND,
	OVERLAY_REFRESH_VSYNC,
	OVERLAY_REFRESH_VSYNC_HALF,
	OVERLAY_REFRESH_VSYNC_QUARTER
};

enum {
	OVERLAY_FRAMEBUF,
	OVERLAY_DIRECTOUT
};

/* system interrupts */
#define INTR_OVERLAY0_DONE		BIT(0)
#define INTR_OVERLAY1_DONE		BIT(1)
#define INTR_DMA_S_DONE			BIT(2)
#define INTR_DMA_E_DONE			BIT(3)
#define INTR_DMA_P_DONE			BIT(4)
#define INTR_VG1_HISTOGRAM		BIT(5)
#define INTR_VG2_HISTOGRAM		BIT(6)
#define INTR_PRIMARY_VSYNC		BIT(7)
#define INTR_PRIMARY_INTF_UDERRUN	BIT(8)
#define INTR_EXTERNAL_VSYNC		BIT(9)
#define INTR_EXTERNAL_INTF_UDERRUN	BIT(10)
#define INTR_PRIMARY_READ_PTR		BIT(11)
#define INTR_DMA_P_HISTOGRAM		BIT(17)

/* histogram interrupts */
#define INTR_HIST_DONE			BIT(1)
#define INTR_HIST_RESET_SEQ_DONE	BIT(0)


#ifdef CONFIG_FB_MSM_OVERLAY
#define MDP4_ANY_INTR_MASK	(INTR_OVERLAY0_DONE|INTR_DMA_S_DONE | \
					INTR_DMA_P_HISTOGRAM)
#else
#define MDP4_ANY_INTR_MASK	(INTR_DMA_P_DONE| \
				INTR_DMA_P_HISTOGRAM)
#endif

enum {
	OVERLAY_PIPE_RGB1,
	OVERLAY_PIPE_RGB2,
	OVERLAY_PIPE_VG1,	/* video/graphic */
	OVERLAY_PIPE_VG2,
	OVERLAY_PIPE_MAX
};

/* 2 VG pipes can be shared by RGB and VIDEO */
#define MDP4_MAX_PIPE (OVERLAY_PIPE_MAX + 2)

#define OVERLAY_TYPE_RGB	0x01
#define	OVERLAY_TYPE_VIDEO	0x02

enum {
	MDP4_MIXER0,
	MDP4_MIXER1,
	MDP4_MIXER_MAX
};

#define MDP4_MAX_MIXER	2

enum {
	OVERLAY_PLANE_INTERLEAVED,
	OVERLAY_PLANE_PLANAR,
	OVERLAY_PLANE_PSEUDO_PLANAR
};

enum {
	MDP4_MIXER_STAGE_UNUNSED,	/* pipe not used */
	MDP4_MIXER_STAGE_BASE,
	MDP4_MIXER_STAGE0,	/* zorder 0 */
	MDP4_MIXER_STAGE1,	/* zorder 1 */
	MDP4_MIXER_STAGE2	/* zorder 2 */
};

#define MDP4_MAX_STAGE	4

enum {
	MDP4_FRAME_FORMAT_LINEAR,
	MDP4_FRAME_FORMAT_ARGB_TILE,
	MDP4_FRAME_FORMAT_VIDEO_SUPERTILE
};

enum {
	MDP4_CHROMA_RGB,
	MDP4_CHROMA_H2V1,
	MDP4_CHROMA_H1V2,
	MDP4_CHROMA_420
};

#define MDP4_BLEND_BG_TRANSP_EN		BIT(9)
#define MDP4_BLEND_FG_TRANSP_EN		BIT(8)
#define MDP4_BLEND_BG_MOD_ALPHA		BIT(7)
#define MDP4_BLEND_BG_INV_ALPHA		BIT(6)
#define MDP4_BLEND_BG_ALPHA_FG_CONST	(0 << 4)
#define MDP4_BLEND_BG_ALPHA_BG_CONST	(1 << 4)
#define MDP4_BLEND_BG_ALPHA_FG_PIXEL	(2 << 4)
#define MDP4_BLEND_BG_ALPHA_BG_PIXEL	(3 << 4)
#define MDP4_BLEND_FG_MOD_ALPHA		BIT(3)
#define MDP4_BLEND_FG_INV_ALPHA		BIT(2)
#define MDP4_BLEND_FG_ALPHA_FG_CONST	(0 << 0)
#define MDP4_BLEND_FG_ALPHA_BG_CONST	(1 << 0)
#define MDP4_BLEND_FG_ALPHA_FG_PIXEL	(2 << 0)
#define MDP4_BLEND_FG_ALPHA_BG_PIXEL	(3 << 0)

#define MDP4_FORMAT_SOLID_FILL		BIT(22)
#define MDP4_FORMAT_UNPACK_ALIGN_MSB	BIT(18)
#define MDP4_FORMAT_UNPACK_TIGHT	BIT(17)
#define MDP4_FORMAT_90_ROTATED		BIT(12)
#define MDP4_FORMAT_ALPHA_ENABLE	BIT(8)

#define MDP4_OP_DEINT_ODD_REF  	BIT(19)
#define MDP4_OP_DEINT_EN	BIT(18)
#define MDP4_OP_IGC_LUT_EN	BIT(16)
#define MDP4_OP_DITHER_EN     	BIT(15)
#define MDP4_OP_FLIP_UD		BIT(14)
#define MDP4_OP_FLIP_LR		BIT(13)
#define MDP4_OP_CSC_EN		BIT(11)
#define MDP4_OP_SRC_DATA_YCBCR	BIT(9)
#define MDP4_OP_SCALEY_FIR 		(0 << 4)
#define MDP4_OP_SCALEY_MN_PHASE 	(1 << 4)
#define MDP4_OP_SCALEY_PIXEL_RPT	(2 << 4)
#define MDP4_OP_SCALEX_FIR 		(0 << 2)
#define MDP4_OP_SCALEX_MN_PHASE 	(1 << 2)
#define MDP4_OP_SCALEX_PIXEL_RPT 	(2 << 2)
#define MDP4_OP_SCALEY_EN	BIT(1)
#define MDP4_OP_SCALEX_EN	BIT(0)

#define MDP4_PIPE_PER_MIXER	2

#define MDP4_MAX_PLANE		4


struct mdp4_overlay_pipe {
	uint32 pipe_used;
	uint32 pipe_type;		/* rgb, video/graphic */
	uint32 pipe_num;
	uint32 pipe_ndx;
	uint32 mixer_num;		/* which mixer used */
	uint32 mixer_stage;		/* which stage of mixer used */
	uint32 src_format;
	uint32 src_width;	/* source img width */
	uint32 src_height;	/* source img height */
	uint32 src_w;		/* roi */
	uint32 src_h;		/* roi */
	uint32 src_x;		/* roi */
	uint32 src_y;		/* roi */
	uint32 dst_w;		/* roi */
	uint32 dst_h;		/* roi */
	uint32 dst_x;		/* roi */
	uint32 dst_y;		/* roi */
	uint32 flags;
	uint32 op_mode;
	uint32 transp;
	uint32 blend_op;
	uint32 phasex_step;
	uint32 phasey_step;
	uint32 alpha;
	uint32 is_fg;		/* control alpha & color key */
	uint32 srcp0_addr;	/* interleave, luma */
	uint32 srcp0_ystride;
	uint32 srcp1_addr;	/* pseudoplanar, chroma plane */
	uint32 srcp1_ystride;
	uint32 srcp2_addr;	/* planar color 2*/
	uint32 srcp2_ystride;
	uint32 srcp3_addr;	/* alpha/color 3 */
	uint32 srcp3_ystride;
	uint32 fetch_plane;
	uint32 frame_format;		/* video */
	uint32 chroma_site;		/* video */
	uint32 chroma_sample;		/* video */
	uint32 solid_fill;
	uint32 vc1_reduce;		/* video */
	uint32 unpack_align_msb;/* 0 to LSB, 1 to MSB */
	uint32 unpack_tight;/* 0 for loose, 1 for tight */
	uint32 unpack_count;/* 0 = 1 component, 1 = 2 component ... */
	uint32 rotated_90; /* has been rotated 90 degree */
	uint32 bpp;	/* byte per pixel */
	uint32 alpha_enable;/*  source has alpha */
	/*
	 * number of bits for source component,
	 * 0 = 1 bit, 1 = 2 bits, 2 = 6 bits, 3 = 8 bits
	 */
	uint32 a_bit;	/* component 3, alpha */
	uint32 r_bit;	/* component 2, R_Cr */
	uint32 b_bit;	/* component 1, B_Cb */
	uint32 g_bit;	/* component 0, G_lumz */
	/*
	 * unpack pattern
	 * A = C3, R = C2, B = C1, G = C0
	 */
	uint32 element3; /* 0 = C0, 1 = C1, 2 = C2, 3 = C3 */
	uint32 element2; /* 0 = C0, 1 = C1, 2 = C2, 3 = C3 */
	uint32 element1; /* 0 = C0, 1 = C1, 2 = C2, 3 = C3 */
	uint32 element0; /* 0 = C0, 1 = C1, 2 = C2, 3 = C3 */
	struct completion comp;
	ulong blt_addr; /* blt mode addr */
	uint32 blt_cnt;
	uint32 blt_end;
	struct completion dmas_comp;
	struct mdp_overlay req_data;
};

struct mdp4_pipe_desc {
	uint32 ref_cnt;
	struct mdp4_overlay_pipe *player;
};

struct mdp4_statistic {
	ulong intr_tot;
	ulong intr_dma_p;
	ulong intr_dma_s;
	ulong intr_dma_e;
	ulong intr_overlay0;
	ulong intr_overlay1;
	ulong intr_underrun_p;	/* Primary interface */
	ulong intr_underrun_e;	/* external interface */
	ulong kickoff_mddi;
	ulong kickoff_piggy;
	ulong kickoff_lcdc;
	ulong kickoff_dtv;
	ulong kickoff_atv;
	ulong kickoff_dsi;
	ulong overlay_set[MDP4_MIXER_MAX];
	ulong overlay_unset[MDP4_MIXER_MAX];
	ulong overlay_play[MDP4_MIXER_MAX];
	ulong pipe[MDP4_MAX_PIPE];
	ulong err_mixer;
	ulong err_zorder;
	ulong err_size;
	ulong err_scale;
	ulong err_format;
};

struct mdp4_overlay_pipe *mdp4_overlay_ndx2pipe(int ndx);
void mdp4_sw_reset(unsigned long bits);
void mdp4_display_intf_sel(int output, unsigned long intf);
void mdp4_overlay_cfg(int layer, int blt_mode, int refresh, int direct_out);
void mdp4_ebi2_lcd_setup(int lcd, unsigned long base, int ystride);
void mdp4_mddi_setup(int which, unsigned long id);
unsigned long mdp4_display_status(void);
void mdp4_enable_clk_irq(void);
void mdp4_disable_clk_irq(void);
void mdp4_dma_p_update(struct msm_fb_data_type *mfd);
void mdp4_dma_s_update(struct msm_fb_data_type *mfd);
void mdp_pipe_ctrl(MDP_BLOCK_TYPE block, MDP_BLOCK_POWER_STATE state,
		   boolean isr);
void mdp4_pipe_kickoff(uint32 pipe, struct msm_fb_data_type *mfd);
int mdp4_lcdc_on(struct platform_device *pdev);
int mdp4_lcdc_off(struct platform_device *pdev);
void mdp4_lcdc_update(struct msm_fb_data_type *mfd);
void mdp4_intr_clear_set(ulong clear, ulong set);
void mdp4_dma_p_cfg(void);
void mdp4_hw_init(void);
void mdp4_isr_read(int);
void mdp4_clear_lcdc(void);
void mdp4_mixer_blend_init(int mixer_num);
void mdp4_vg_qseed_init(int vg_num);
void mdp4_vg_csc_setup(int vp_num);
void mdp4_mixer1_csc_setup(void);
void mdp4_vg_csc_update(struct mdp_csc *p);
irqreturn_t mdp4_isr(int irq, void *ptr);
void mdp4_overlay_format_to_pipe(uint32 format, struct mdp4_overlay_pipe *pipe);
uint32 mdp4_overlay_format(struct mdp4_overlay_pipe *pipe);
uint32 mdp4_overlay_unpack_pattern(struct mdp4_overlay_pipe *pipe);
uint32 mdp4_overlay_op_mode(struct mdp4_overlay_pipe *pipe);
void mdp4_lcdc_overlay(struct msm_fb_data_type *mfd);
void mdp4_dtv_overlay(struct msm_fb_data_type *mfd);
int mdp4_dtv_on(struct platform_device *pdev);
int mdp4_dtv_off(struct platform_device *pdev);
int mdp4_dtv_lcdc_enable(struct platform_device *pdev, int enable);
void mdp4_atv_overlay(struct msm_fb_data_type *mfd);
int mdp4_atv_on(struct platform_device *pdev);
int mdp4_atv_off(struct platform_device *pdev);
void mdp4_dsi_video_overlay(struct msm_fb_data_type *mfd);
int mdp4_dsi_video_on(struct platform_device *pdev);
int mdp4_dsi_video_off(struct platform_device *pdev);
void mdp4_overlay0_done_dsi_video(void);
void mdp4_dsi_cmd_overlay(struct msm_fb_data_type *mfd);
int mdp4_dsi_cmd_on(struct platform_device *pdev);
int mdp4_dsi_cmd_off(struct platform_device *pdev);
void mdp4_overlay_rgb_setup(struct mdp4_overlay_pipe *pipe);
void mdp4_overlay_reg_flush(struct mdp4_overlay_pipe *pipe, int all);
void mdp4_mixer_blend_setup(struct mdp4_overlay_pipe *pipe);
struct mdp4_overlay_pipe *mdp4_overlay_stage_pipe(int mixer, int stage);
void mdp4_mixer_stage_up(struct mdp4_overlay_pipe *pipe);
void mdp4_mixer_stage_down(struct mdp4_overlay_pipe *pipe);
int mdp4_mixer_stage_can_run(struct mdp4_overlay_pipe *pipe);
void mdp4_overlayproc_cfg(struct mdp4_overlay_pipe *pipe);
void mdp4_mddi_overlay(struct msm_fb_data_type *mfd);
int mdp4_overlay_format2type(uint32 format);
int mdp4_overlay_format2pipe(struct mdp4_overlay_pipe *pipe);
int mdp4_overlay_get(struct fb_info *info, struct mdp_overlay *req);
int mdp4_overlay_set(struct fb_info *info, struct mdp_overlay *req);
int mdp4_overlay_unset(struct fb_info *info, int ndx);
void mdp4_overlay_dtv_wait_for_ov(struct msm_fb_data_type *mfd,
	struct mdp4_overlay_pipe *pipe);
void mdp4_overlay_dtv_vsync_push(struct msm_fb_data_type *mfd,
	struct mdp4_overlay_pipe *pipe);
void mdp4_overlay_dtv_ov_done_push(struct msm_fb_data_type *mfd,
	struct mdp4_overlay_pipe *pipe);
int mdp4_overlay_play_wait(struct fb_info *info,
	struct msmfb_overlay_data *req);
int mdp4_overlay_play(struct fb_info *info, struct msmfb_overlay_data *req,
				struct file **pp_src_file);
int mdp4_overlay_refresh(struct fb_info *info, int ndx);
struct mdp4_overlay_pipe *mdp4_overlay_pipe_alloc(int ptype, boolean usevg);
void mdp4_overlay_pipe_free(struct mdp4_overlay_pipe *pipe);
void mdp4_overlay_dmap_cfg(struct msm_fb_data_type *mfd, int lcdc);
void mdp4_overlay_dmap_xy(struct mdp4_overlay_pipe *pipe);
void mdp4_overlay_dmae_cfg(struct msm_fb_data_type *mfd, int atv);
void mdp4_overlay_dmae_xy(struct mdp4_overlay_pipe *pipe);
int mdp4_overlay_pipe_staged(int mixer);
void mdp4_overlay0_done_lcdc(void);
void mdp4_overlay0_done_mddi(void);
void mdp4_dma_p_done_mddi(void);
void mdp4_dma_s_done_mddi(void);
void mdp4_external_vsync_dtv(void);
void mdp4_overlay1_done_dtv(void);
void mdp4_overlay1_done_atv(void);
void mdp4_mddi_overlay_restore(void);
void mdp4_mddi_overlay_dmas_restore(void);
void mdp4_mddi_dma_busy_wait(struct msm_fb_data_type *mfd,
				struct mdp4_overlay_pipe *pipe);
void mdp4_mddi_overlay_kickoff(struct msm_fb_data_type *mfd,
				struct mdp4_overlay_pipe *pipe);
void mdp4_rgb_igc_lut_setup(int num);
void mdp4_vg_igc_lut_setup(int num);
void mdp4_mixer_gc_lut_setup(int mixer_num);
void mdp4_fetch_cfg(uint32 clk);
uint32 mdp4_rgb_igc_lut_cvt(uint32 ndx);
void mdp4_vg_qseed_init(int);
void mdp4_overlay_panel_mode(int mixer_num, uint32 mode);
int mdp4_overlay_mixer_play(int mixer_num);
uint32 mdp4_overlay_panel_list(void);
void mdp4_lcdc_overlay_kickoff(struct msm_fb_data_type *mfd,
			struct mdp4_overlay_pipe *pipe);

void mdp4_mddi_kickoff_video(struct msm_fb_data_type *mfd,
                                struct mdp4_overlay_pipe *pipe);

void mdp4_mddi_read_ptr_intr(void);

void mdp_dmap_vsync_set(int enable);
int mdp_dmap_vsync_get(void);
void mdp_hw_cursor_done(void);
void mdp_hw_cursor_init(void);

int mdp_ppp_blit(struct fb_info *info, struct mdp_blit_req *req);
void mdp_vsync_config_update(struct msm_panel_info *pinfo);
void mdp4_overlay_resource_release(void);
#endif /* MDP_H */
