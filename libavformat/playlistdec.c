/*
 * Concat demuxer
 * Copyright (c) 2012 Nicolas George
 * 
 * Playlist demuxer 
 * Copyright (c) 2017 Sebastien Biziou
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FFmpeg; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/timestamp.h"
#include "avformat.h"
#include "internal.h"
#include "url.h"

typedef enum PlaylistMatchMode {
    MATCH_ONE_TO_ONE,
    MATCH_EXACT_ID,
} PlaylistMatchMode;

typedef struct PlaylistStream {
    AVBSFContext *bsf;
    int out_stream_index;
} PlaylistStream;

typedef struct {
    char *url;
    int64_t start_time;
    int64_t file_start_time;
    int64_t file_inpoint;
    int64_t duration;
    PlaylistStream *streams;
    int64_t inpoint;
    int64_t outpoint;
    AVDictionary *metadata;
    int nb_streams;
} PlaylistFile;

typedef struct {
    AVClass *class;
    PlaylistFile *files;
    PlaylistFile *cur_file;
    unsigned nb_files;
    AVFormatContext *avf;
    char* path;
    int loop;
    int loops;
    int seekable;
    int eof;
    PlaylistMatchMode stream_match_mode;
    unsigned auto_convert;
    int segment_time_metadata;
} PlaylistContext;

#define FAIL(retcode) do { ret = (retcode); goto fail; } while(0)

static int playlist_probe(AVProbeData *probe)
{
    return memcmp(probe->buf, "ffplaylist version 1.0", 20) ?
           0 : AVPROBE_SCORE_MAX;
}

static int playlist_free_file(PlaylistFile *file) 
{
    unsigned i;

    av_freep(&file->url);
    for (i = 0; i < file->nb_streams; i++) {
        if (file->streams[i].bsf)
            av_bsf_free(&file->streams[i].bsf);
    }
    av_freep(&file->streams);
    av_dict_free(&file->metadata);
    av_freep(file);

    return 0;
}

static int playlist_read_close(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    unsigned i;

    for (i = 0; i < playlist->nb_files; i++) {
        playlist_free_file(&playlist->files[i]);
    }
    if (playlist->avf)
        avformat_close_input(&playlist->avf);
    av_freep(&playlist->files);
    av_freep(&playlist->path);
    return 0;
}

static char* playlist_file(AVFormatContext *avf, const char *ext) 
{
    PlaylistContext *playlist = avf->priv_data;
    size_t left_len, file_len;
    char *file = NULL;
    char *dotpos = NULL;

    dotpos = strrchr(playlist->path, '.');
    if(dotpos != NULL) {
        left_len = (dotpos + 2) - playlist->path;
        file_len = left_len + strlen(ext);
        if (!(file = av_malloc(file_len))) 
            return NULL;
        av_strlcpy(file, playlist->path, left_len);
        av_strlcat(file, ext, file_len);

        return file;
    }

    return NULL;
}

static void playlist_init(AVFormatContext *avf) 
{
    PlaylistContext *playlist = avf->priv_data;
    AVIOContext *pb = NULL;    
    char *pid_file = NULL;
    int ret = 0;

    // init playlist
    playlist->loops = 0;
    playlist->stream_match_mode = avf->nb_streams ? MATCH_EXACT_ID : MATCH_ONE_TO_ONE;

    // pid file
    if((pid_file = playlist_file(avf, "pid")) == NULL) {
        av_log(avf, AV_LOG_ERROR, "can't get pid file name\n");     
    }
    else {
        av_log(avf, AV_LOG_INFO, "pid file : %s\n", pid_file);
        if((ret = avio_open(&pb, pid_file, AVIO_FLAG_WRITE)) < 0) {       
            av_log(avf, AV_LOG_ERROR, "can't write pid file\n");     
        }
        else {
            avio_printf(pb, "%d", getpid());
            avio_close(pb);
        }
    }
}

static char *get_keyword(uint8_t **cursor)
{
    char *ret = *cursor += strspn(*cursor, SPACE_CHARS);
    *cursor += strcspn(*cursor, SPACE_CHARS);
    if (**cursor) {
        *((*cursor)++) = 0;
        *cursor += strspn(*cursor, SPACE_CHARS);
    }
    return ret;
}

static int add_file(AVFormatContext *avf, char *filename, PlaylistFile **rfile,
                    unsigned *nb_files_alloc)
{
    PlaylistContext *playlist = avf->priv_data;
    PlaylistFile *file;
    char *url = NULL;
    const char *proto;
    size_t url_len, proto_len;
    int ret;

    av_log(avf, AV_LOG_INFO, "add file '%s'\n", filename);

    proto = avio_find_protocol_name(filename);
    proto_len = proto ? strlen(proto) : 0;
    if (!memcmp(filename, proto, proto_len) &&
        (filename[proto_len] == ':' || filename[proto_len] == ',')) {
        url = filename;
        filename = NULL;
    } else {
        url_len = strlen(avf->filename) + strlen(filename) + 16;
        if (!(url = av_malloc(url_len)))
            FAIL(AVERROR(ENOMEM));
        ff_make_absolute_url(url, url_len, avf->filename, filename);
        av_freep(&filename);
    }

    if (playlist->nb_files >= *nb_files_alloc) {
        size_t n = FFMAX(*nb_files_alloc * 2, 16);
        PlaylistFile *new_files;
        if (n <= playlist->nb_files || n > SIZE_MAX / sizeof(*playlist->files) ||
            !(new_files = av_realloc(playlist->files, n * sizeof(*playlist->files))))
            FAIL(AVERROR(ENOMEM));
        playlist->files = new_files;
        *nb_files_alloc = n;
    }

    file = &playlist->files[playlist->nb_files++];
    memset(file, 0, sizeof(*file));
    *rfile = file;

    file->url        = url;
    file->start_time = AV_NOPTS_VALUE;
    file->duration   = AV_NOPTS_VALUE;
    file->inpoint    = AV_NOPTS_VALUE;
    file->outpoint   = AV_NOPTS_VALUE;

    return 0;

fail:
    av_free(url);
    av_free(filename);
    return ret;
}

static int copy_stream_props(AVStream *st, AVStream *source_st)
{
    int ret;

    if (st->codecpar->codec_id || !source_st->codecpar->codec_id) {
        if (st->codecpar->extradata_size < source_st->codecpar->extradata_size) {
            if (st->codecpar->extradata) {
                av_freep(&st->codecpar->extradata);
                st->codecpar->extradata_size = 0;
            }
            ret = ff_alloc_extradata(st->codecpar,
                                     source_st->codecpar->extradata_size);
            if (ret < 0)
                return ret;
        }
        memcpy(st->codecpar->extradata, source_st->codecpar->extradata,
               source_st->codecpar->extradata_size);
        return 0;
    }
    if ((ret = avcodec_parameters_copy(st->codecpar, source_st->codecpar)) < 0)
        return ret;
    st->r_frame_rate        = source_st->r_frame_rate;
    st->avg_frame_rate      = source_st->avg_frame_rate;
    st->time_base           = source_st->time_base;
    st->sample_aspect_ratio = source_st->sample_aspect_ratio;

    av_dict_copy(&st->metadata, source_st->metadata, 0);
    return 0;
}

static int detect_stream_specific(AVFormatContext *avf, int idx)
{
    PlaylistContext *playlist = avf->priv_data;
    AVStream *st = playlist->avf->streams[idx];
    PlaylistStream *cs = &playlist->cur_file->streams[idx];
    const AVBitStreamFilter *filter;
    AVBSFContext *bsf;
    int ret;

    if (playlist->auto_convert && st->codecpar->codec_id == AV_CODEC_ID_H264) {
        if (!st->codecpar->extradata_size                                                ||
            (st->codecpar->extradata_size >= 3 && AV_RB24(st->codecpar->extradata) == 1) ||
            (st->codecpar->extradata_size >= 4 && AV_RB32(st->codecpar->extradata) == 1))
            return 0;
        av_log(playlist->avf, AV_LOG_INFO,
               "Auto-inserting h264_mp4toannexb bitstream filter\n");
        filter = av_bsf_get_by_name("h264_mp4toannexb");
        if (!filter) {
            av_log(avf, AV_LOG_ERROR, "h264_mp4toannexb bitstream filter "
                   "required for H.264 streams\n");
            return AVERROR_BSF_NOT_FOUND;
        }
        ret = av_bsf_alloc(filter, &bsf);
        if (ret < 0)
            return ret;
        cs->bsf = bsf;

        ret = avcodec_parameters_copy(bsf->par_in, st->codecpar);
        if (ret < 0)
           return ret;

        ret = av_bsf_init(bsf);
        if (ret < 0)
            return ret;

        ret = avcodec_parameters_copy(st->codecpar, bsf->par_out);
        if (ret < 0)
            return ret;
    }
    return 0;
}

static int match_streams_one_to_one(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    AVStream *st;
    int i, ret;

    for (i = playlist->cur_file->nb_streams; i < playlist->avf->nb_streams; i++) {
        if (i < avf->nb_streams) {
            st = avf->streams[i];
        } else {
            if (!(st = avformat_new_stream(avf, NULL)))
                return AVERROR(ENOMEM);
        }
        if ((ret = copy_stream_props(st, playlist->avf->streams[i])) < 0)
            return ret;
        playlist->cur_file->streams[i].out_stream_index = i;
    }
    return 0;
}

static int match_streams_exact_id(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    AVStream *st;
    int i, j, ret;

    for (i = playlist->cur_file->nb_streams; i < playlist->avf->nb_streams; i++) {
        st = playlist->avf->streams[i];
        for (j = 0; j < avf->nb_streams; j++) {
            if (avf->streams[j]->id == st->id) {
                av_log(avf, AV_LOG_VERBOSE,
                       "Match slave stream #%d with stream #%d id 0x%x\n",
                       i, j, st->id);
                if ((ret = copy_stream_props(avf->streams[j], st)) < 0)
                    return ret;
                playlist->cur_file->streams[i].out_stream_index = j;
            }
        }
    }
    return 0;
}

static int match_streams(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    PlaylistStream *map;
    int i, ret;

    if (playlist->cur_file->nb_streams >= playlist->avf->nb_streams)
        return 0;
    map = av_realloc(playlist->cur_file->streams,
                     playlist->avf->nb_streams * sizeof(*map));
    if (!map)
        return AVERROR(ENOMEM);
    playlist->cur_file->streams = map;
    memset(map + playlist->cur_file->nb_streams, 0,
           (playlist->avf->nb_streams - playlist->cur_file->nb_streams) * sizeof(*map));

    for (i = playlist->cur_file->nb_streams; i < playlist->avf->nb_streams; i++) {
        map[i].out_stream_index = -1;
        if ((ret = detect_stream_specific(avf, i)) < 0)
            return ret;
    }
    switch (playlist->stream_match_mode) {
    case MATCH_ONE_TO_ONE:
        ret = match_streams_one_to_one(avf);
        break;
    case MATCH_EXACT_ID:
        ret = match_streams_exact_id(avf);
        break;
    default:
        ret = AVERROR_BUG;
    }
    if (ret < 0)
        return ret;
    playlist->cur_file->nb_streams = playlist->avf->nb_streams;
    return 0;
}

static int open_file(AVFormatContext *avf, unsigned fileno)
{
    PlaylistContext *playlist = avf->priv_data;
    PlaylistFile *file = &playlist->files[fileno];
    AVIOContext *pb = NULL;  
    char* current_file;  
    int ret;

    if (playlist->avf)
        avformat_close_input(&playlist->avf);

    playlist->avf = avformat_alloc_context();
    if (!playlist->avf)
        return AVERROR(ENOMEM);

    playlist->avf->flags |= avf->flags & ~AVFMT_FLAG_CUSTOM_IO;
    playlist->avf->interrupt_callback = avf->interrupt_callback;

    if ((ret = ff_copy_whiteblacklists(playlist->avf, avf)) < 0)
        return ret;

    if ((ret = avformat_open_input(&playlist->avf, file->url, NULL, NULL)) < 0 ||
        (ret = avformat_find_stream_info(playlist->avf, NULL)) < 0) {
        av_log(avf, AV_LOG_ERROR, "Impossible to open '%s'\n", file->url);
        avformat_close_input(&playlist->avf);
        return ret;
    }
    playlist->cur_file = file;
    if (file->start_time == AV_NOPTS_VALUE)
        file->start_time = !fileno ? 0 :
                           playlist->files[fileno - 1].start_time +
                           playlist->files[fileno - 1].duration;
    file->file_start_time = (playlist->avf->start_time == AV_NOPTS_VALUE) ? 0 : playlist->avf->start_time;
    file->file_inpoint = (file->inpoint == AV_NOPTS_VALUE) ? file->file_start_time : file->inpoint;
    if (file->duration == AV_NOPTS_VALUE && file->outpoint != AV_NOPTS_VALUE)
        file->duration = file->outpoint - file->file_inpoint;

    if (playlist->segment_time_metadata) {
        av_dict_set_int(&file->metadata, "lavf.playlistdec.start_time", file->start_time, 0);
        if (file->duration != AV_NOPTS_VALUE)
            av_dict_set_int(&file->metadata, "lavf.playlistdec.duration", file->duration, 0);
    }

    if ((ret = match_streams(avf)) < 0)
        return ret;
    if (file->inpoint != AV_NOPTS_VALUE) {
       if ((ret = avformat_seek_file(playlist->avf, -1, INT64_MIN, file->inpoint, file->inpoint, 0)) < 0)
           return ret;
    }
    // Free previous file
    if(fileno > 0) {
        int previous = fileno - 1;
        playlist_free_file(&playlist->files[previous]);
    }
    // Current file
    if((current_file = playlist_file(avf, "current")) == NULL) {
        av_log(avf, AV_LOG_ERROR, "can't get current file name\n");      
    }
    else {
        av_log(avf, AV_LOG_INFO, "pid file : %s\n", current_file);
        if((ret = avio_open(&pb, current_file, AVIO_FLAG_WRITE)) < 0) {       
            av_log(avf, AV_LOG_ERROR, "can't write current file\n");     
        }
        else {
            avio_printf(pb, "%s", file->url);
            avio_close(pb);
        }
    }
    return 0;
}

static int playlist_read_file(AVFormatContext *avf, char *path) 
{
    PlaylistContext *playlist = avf->priv_data;
    uint8_t buf[4096];
    uint8_t *cursor, *keyword;
    int ret, line = 0, i;
    unsigned nb_files_alloc = 0;
    PlaylistFile *file = NULL;
    int64_t time = 0;
    AVIOContext *pb = NULL;

    if((ret = avio_open(&pb, path, AVIO_FLAG_READ)) < 0) {
        goto fail;
    }

    nb_files_alloc = playlist->nb_files;

    while (1) {

        if ((ret = ff_get_line(pb, buf, sizeof(buf))) <= 0) {        
            break;
        }

        line++;
        cursor = buf;
        keyword = get_keyword(&cursor);
        if (!*keyword || *keyword == '#')
            continue;

        if (!strcmp(keyword, "file")) {
            char *filename = av_get_token((const char **)&cursor, SPACE_CHARS);
            if (!filename) {
                av_log(avf, AV_LOG_ERROR, "Line %d: filename required\n", line);
                FAIL(AVERROR_INVALIDDATA);
            }
            if ((ret = add_file(avf, filename, &file, &nb_files_alloc)) < 0)
                goto fail;
        } else if (!strcmp(keyword, "duration") || !strcmp(keyword, "inpoint") || !strcmp(keyword, "outpoint")) {
            char *dur_str = get_keyword(&cursor);
            int64_t dur;
            if (!file) {
                av_log(avf, AV_LOG_ERROR, "Line %d: %s without file\n",
                       line, keyword);
                FAIL(AVERROR_INVALIDDATA);
            }
            if ((ret = av_parse_time(&dur, dur_str, 1)) < 0) {
                av_log(avf, AV_LOG_ERROR, "Line %d: invalid %s '%s'\n",
                       line, keyword, dur_str);
                goto fail;
            }
            if (!strcmp(keyword, "duration"))
                file->duration = dur;
            else if (!strcmp(keyword, "inpoint"))
                file->inpoint = dur;
            else if (!strcmp(keyword, "outpoint"))
                file->outpoint = dur;
        } else if (!strcmp(keyword, "file_packet_metadata")) {
            char *metadata;
            if (!file) {
                av_log(avf, AV_LOG_ERROR, "Line %d: %s without file\n",
                       line, keyword);
                FAIL(AVERROR_INVALIDDATA);
            }
            metadata = av_get_token((const char **)&cursor, SPACE_CHARS);
            if (!metadata) {
                av_log(avf, AV_LOG_ERROR, "Line %d: packet metadata required\n", line);
                FAIL(AVERROR_INVALIDDATA);
            }
            if ((ret = av_dict_parse_string(&file->metadata, metadata, "=", "", 0)) < 0) {
                av_log(avf, AV_LOG_ERROR, "Line %d: failed to parse metadata string\n", line);
                av_freep(&metadata);
                FAIL(AVERROR_INVALIDDATA);
            }
            av_freep(&metadata);
        } else if (!strcmp(keyword, "stream")) {
            if (!avformat_new_stream(avf, NULL))
                FAIL(AVERROR(ENOMEM));
        } else if (!strcmp(keyword, "exact_stream_id")) {
            if (!avf->nb_streams) {
                av_log(avf, AV_LOG_ERROR, "Line %d: exact_stream_id without stream\n",
                       line);
                FAIL(AVERROR_INVALIDDATA);
            }
            avf->streams[avf->nb_streams - 1]->id =
                strtol(get_keyword(&cursor), NULL, 0);
        } else if (!strcmp(keyword, "ffconcat")) {
            char *ver_kw  = get_keyword(&cursor);
            char *ver_val = get_keyword(&cursor);
            if (strcmp(ver_kw, "version") || strcmp(ver_val, "1.0")) {
                av_log(avf, AV_LOG_ERROR, "Line %d: invalid version\n", line);
                FAIL(AVERROR_INVALIDDATA);
            }
        } else {
            av_log(avf, AV_LOG_ERROR, "Line %d: unknown keyword '%s'\n",
                   line, keyword);
            FAIL(AVERROR_INVALIDDATA);
        }
    }

    avio_close(pb);

    if (ret < 0)
        goto fail;

    if (!playlist->nb_files)
        FAIL(AVERROR_INVALIDDATA);

    for (i = 0; i < playlist->nb_files; i++) {
        if (playlist->files[i].start_time == AV_NOPTS_VALUE)
            playlist->files[i].start_time = time;
        else
            time = playlist->files[i].start_time;
        if (playlist->files[i].duration == AV_NOPTS_VALUE) {
            if (playlist->files[i].inpoint == AV_NOPTS_VALUE || playlist->files[i].outpoint == AV_NOPTS_VALUE)
                break;
            playlist->files[i].duration = playlist->files[i].outpoint - playlist->files[i].inpoint;
        }
        time += playlist->files[i].duration;
    }
    if (i == playlist->nb_files)
        avf->duration = time;

    return 0;

fail:
    playlist_read_close(avf);
    return ret;
}

static int playlist_update(AVFormatContext *avf) 
{
    PlaylistContext *playlist = avf->priv_data;

    return playlist_read_file(avf, playlist->path);
}

static int playlist_read_header(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    int ret = 0;
 
    playlist_init(avf);

    if((ret = playlist_read_file(avf, playlist->path)) < 0)
        goto fail;

    if ((ret = open_file(avf, 0)) < 0)
        goto fail;

    return 0;

fail:
    playlist_read_close(avf);
    return ret;
}

static int open_next_file(AVFormatContext *avf)
{
    PlaylistContext *playlist = avf->priv_data;
    unsigned fileno = playlist->cur_file - playlist->files;

    if (playlist->cur_file->duration == AV_NOPTS_VALUE)
        playlist->cur_file->duration = playlist->avf->duration - (playlist->cur_file->file_inpoint - playlist->cur_file->file_start_time);

    if(playlist->loop > 0)
        playlist->loop--;
    
    ++fileno;

    if (fileno >= playlist->nb_files) {
        if(playlist->loop != 0) {
            playlist->loops++;
            playlist_update(avf);
        }
        else {
            playlist->eof = 1;
            return AVERROR_EOF;
        }
    }

    av_log(avf, AV_LOG_INFO, "== loop %d, loops: %d, fileno: %d\n", playlist->loop, playlist->loops, fileno);

    return open_file(avf, fileno);
}

static int filter_packet(AVFormatContext *avf, PlaylistStream *cs, AVPacket *pkt)
{
    int ret;

    if (cs->bsf) {
        ret = av_bsf_send_packet(cs->bsf, pkt);
        if (ret < 0) {
            av_log(avf, AV_LOG_ERROR, "h264_mp4toannexb filter "
                   "failed to send input packet\n");
            av_packet_unref(pkt);
            return ret;
        }

        while (!ret)
            ret = av_bsf_receive_packet(cs->bsf, pkt);

        if (ret < 0 && (ret != AVERROR(EAGAIN) && ret != AVERROR_EOF)) {
            av_log(avf, AV_LOG_ERROR, "h264_mp4toannexb filter "
                   "failed to receive output packet\n");
            return ret;
        }
    }
    return 0;
}

/* Returns true if the packet dts is greater or equal to the specified outpoint. */
static int packet_after_outpoint(PlaylistContext *playlist, AVPacket *pkt)
{
    if (playlist->cur_file->outpoint != AV_NOPTS_VALUE && pkt->dts != AV_NOPTS_VALUE) {
        return av_compare_ts(pkt->dts, playlist->avf->streams[pkt->stream_index]->time_base,
                             playlist->cur_file->outpoint, AV_TIME_BASE_Q) >= 0;
    }
    return 0;
}

static int playlist_read_packet(AVFormatContext *avf, AVPacket *pkt)
{
    PlaylistContext *playlist = avf->priv_data;
    int ret;
    int64_t delta;
    PlaylistStream *cs;
    AVStream *st;

    if (playlist->eof)
        return AVERROR_EOF;

    if (!playlist->avf)
        return AVERROR(EIO);

    while (1) {
        ret = av_read_frame(playlist->avf, pkt);
        if (ret == AVERROR_EOF) {
            if ((ret = open_next_file(avf)) < 0)
                return ret;
            continue;
        }
        if (ret < 0)
            return ret;
        if ((ret = match_streams(avf)) < 0) {
            av_packet_unref(pkt);
            return ret;
        }
        if (packet_after_outpoint(playlist, pkt)) {
            av_packet_unref(pkt);
            if ((ret = open_next_file(avf)) < 0)
                return ret;
            continue;
        }
        cs = &playlist->cur_file->streams[pkt->stream_index];
        if (cs->out_stream_index < 0) {
            av_packet_unref(pkt);
            continue;
        }
        pkt->stream_index = cs->out_stream_index;
        break;
    }
    if ((ret = filter_packet(avf, cs, pkt)))
        return ret;

    st = playlist->avf->streams[pkt->stream_index];
    av_log(avf, AV_LOG_DEBUG, "file:%d stream:%d pts:%s pts_time:%s dts:%s dts_time:%s",
           (unsigned)(playlist->cur_file - playlist->files), pkt->stream_index,
           av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base),
           av_ts2str(pkt->dts), av_ts2timestr(pkt->dts, &st->time_base));

    delta = av_rescale_q(playlist->cur_file->start_time - playlist->cur_file->file_inpoint,
                         AV_TIME_BASE_Q,
                         playlist->avf->streams[pkt->stream_index]->time_base);
    if (pkt->pts != AV_NOPTS_VALUE)
        pkt->pts += delta;
    if (pkt->dts != AV_NOPTS_VALUE)
        pkt->dts += delta;
    av_log(avf, AV_LOG_DEBUG, " -> pts:%s pts_time:%s dts:%s dts_time:%s\n",
           av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, &st->time_base),
           av_ts2str(pkt->dts), av_ts2timestr(pkt->dts, &st->time_base));
    if (playlist->cur_file->metadata) {
        uint8_t* metadata;
        int metadata_len;
        char* packed_metadata = av_packet_pack_dictionary(playlist->cur_file->metadata, &metadata_len);
        if (!packed_metadata)
            return AVERROR(ENOMEM);
        if (!(metadata = av_packet_new_side_data(pkt, AV_PKT_DATA_STRINGS_METADATA, metadata_len))) {
            av_freep(&packed_metadata);
            return AVERROR(ENOMEM);
        }
        memcpy(metadata, packed_metadata, metadata_len);
        av_freep(&packed_metadata);
    }
    return ret;
}

static void rescale_interval(AVRational tb_in, AVRational tb_out,
                             int64_t *min_ts, int64_t *ts, int64_t *max_ts)
{
    *ts     = av_rescale_q    (*    ts, tb_in, tb_out);
    *min_ts = av_rescale_q_rnd(*min_ts, tb_in, tb_out,
                               AV_ROUND_UP   | AV_ROUND_PASS_MINMAX);
    *max_ts = av_rescale_q_rnd(*max_ts, tb_in, tb_out,
                               AV_ROUND_DOWN | AV_ROUND_PASS_MINMAX);
}

static int try_seek(AVFormatContext *avf, int stream,
                    int64_t min_ts, int64_t ts, int64_t max_ts, int flags)
{
    PlaylistContext *playlist = avf->priv_data;
    int64_t t0 = playlist->cur_file->start_time - playlist->cur_file->file_inpoint;

    ts -= t0;
    min_ts = min_ts == INT64_MIN ? INT64_MIN : min_ts - t0;
    max_ts = max_ts == INT64_MAX ? INT64_MAX : max_ts - t0;
    if (stream >= 0) {
        if (stream >= playlist->avf->nb_streams)
            return AVERROR(EIO);
        rescale_interval(AV_TIME_BASE_Q, playlist->avf->streams[stream]->time_base,
                         &min_ts, &ts, &max_ts);
    }
    return avformat_seek_file(playlist->avf, stream, min_ts, ts, max_ts, flags);
}

static int real_seek(AVFormatContext *avf, int stream,
                     int64_t min_ts, int64_t ts, int64_t max_ts, int flags, AVFormatContext *cur_avf)
{
    PlaylistContext *playlist = avf->priv_data;
    int ret, left, right;

    if (stream >= 0) {
        if (stream >= avf->nb_streams)
            return AVERROR(EINVAL);
        rescale_interval(avf->streams[stream]->time_base, AV_TIME_BASE_Q,
                         &min_ts, &ts, &max_ts);
    }

    left  = 0;
    right = playlist->nb_files;
    while (right - left > 1) {
        int mid = (left + right) / 2;
        if (ts < playlist->files[mid].start_time)
            right = mid;
        else
            left  = mid;
    }

    if (playlist->cur_file != &playlist->files[left]) {
        if ((ret = open_file(avf, left)) < 0)
            return ret;
    } else {
        playlist->avf = cur_avf;
    }

    ret = try_seek(avf, stream, min_ts, ts, max_ts, flags);
    if (ret < 0 &&
        left < playlist->nb_files - 1 &&
        playlist->files[left + 1].start_time < max_ts) {
        if (playlist->cur_file == &playlist->files[left])
            playlist->avf = NULL;
        if ((ret = open_file(avf, left + 1)) < 0)
            return ret;
        ret = try_seek(avf, stream, min_ts, ts, max_ts, flags);
    }
    return ret;
}

static int playlist_seek(AVFormatContext *avf, int stream,
                       int64_t min_ts, int64_t ts, int64_t max_ts, int flags)
{
    PlaylistContext *playlist = avf->priv_data;
    PlaylistFile *cur_file_saved = playlist->cur_file;
    AVFormatContext *cur_avf_saved = playlist->avf;
    int ret;

    if (!playlist->seekable)
        return AVERROR(ESPIPE); /* XXX: can we use it? */
    if (flags & (AVSEEK_FLAG_BYTE | AVSEEK_FLAG_FRAME))
        return AVERROR(ENOSYS);
    playlist->avf = NULL;
    if ((ret = real_seek(avf, stream, min_ts, ts, max_ts, flags, cur_avf_saved)) < 0) {
        if (playlist->cur_file != cur_file_saved) {
            if (playlist->avf)
                avformat_close_input(&playlist->avf);
        }
        playlist->avf      = cur_avf_saved;
        playlist->cur_file = cur_file_saved;
    } else {
        if (playlist->cur_file != cur_file_saved) {
            avformat_close_input(&cur_avf_saved);
        }
        playlist->eof = 0;
    }
    return ret;
}

#define OFFSET(x) offsetof(PlaylistContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM

static const AVOption options[] = {
    { "path", "path to the playlist file",
      OFFSET(path), AV_OPT_TYPE_STRING, {.str = NULL}, 0, 0, DEC },
    { "loop", "set number of times input playlist shall be looped",
      OFFSET(loop), AV_OPT_TYPE_INT, {.i64 = -1}, -1, INT_MAX, DEC },
    { "auto_convert", "automatically convert bitstream format",
      OFFSET(auto_convert), AV_OPT_TYPE_BOOL, {.i64 = 1}, 0, 1, DEC },
    { "segment_time_metadata", "output file segment start time and duration as packet metadata",
      OFFSET(segment_time_metadata), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, DEC },
    { NULL }
};

static const AVClass playlist_class = {
    .class_name = "playlist demuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};


AVInputFormat ff_playlist_demuxer = {
    .name           = "playlist",
    .long_name      = NULL_IF_CONFIG_SMALL("Playlist demuxer"),
    .priv_data_size = sizeof(PlaylistContext),
    .read_probe     = playlist_probe,
    .read_header    = playlist_read_header,
    .read_packet    = playlist_read_packet,
    .read_close     = playlist_read_close,
    .read_seek2     = playlist_seek,
    .priv_class     = &playlist_class,
};
