package main

import (
	"errors"
	"github.com/zalando/skipper/eskip"
	etcdclient "github.com/zalando/skipper/etcd"
)

type writeClient interface {
	UpsertAll(routes []*eskip.Route) error
	// delete all items in 'routes' that fulfil 'cond'.
	DeleteAllIf(routes []*eskip.Route, cond eskip.RoutePredicate) error
}

var invalidOutput = errors.New("invalid output")

func createWriteClient(out *medium) (writeClient, error) {
	// no output, no client
	if out == nil {
		return nil, nil
	}

	switch out.typ {
	case innkeeper:
		return createInnkeeperClient(out)
	case etcd:
		client := etcdclient.New(urlsToStrings(out.urls), out.path)
		return client, nil
	}
	return nil, invalidOutput
}