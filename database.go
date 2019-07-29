package gw

import (
	"database/sql"
	"fmt"
	"github.com/juju/errors"
	_ "github.com/lib/pq"
	"github.com/mattes/migrate"
	"github.com/mattes/migrate/database/postgres"
	_ "github.com/mattes/migrate/source/file"
	"net/url"
	"regexp"
	"strconv"
)

func Migrate(connection, path string) error {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return err
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithDatabaseInstance(path, "postgres", driver)
	if err != nil {
		return err
	}
	err = m.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			return nil
		} else {
			return err
		}
	}
	return nil
}

const (
	ASC  = "ascend"
	DESC = "descend"
)

type QuerySettings struct {
	Start    int
	Count    int
	Field    string
	Order    string
	Compiled string
}

// Supports ordering and subsetting of queries by building the relevant
// portions of a SELECT query out of URL query args.  Returns a string with
// the relevant clauses, generally suitable for appending to the end of a
// query (without said clauses).
// * start: integer, starting index of query. Defaults to 0.
// * count: integer, max size of query. Defaults to 0, which is unlimited.
//          This will probably change!
// * field: string, name of column to sort by. Default supplied as col arg to
//          function.  Leave arg empty to ignore sorting.
// * order: ("ascend"|"descend") Default supplied as ord arg to function.
func QuerySetHelper(args url.Values, col, ord string) (*QuerySettings, error) {
	var start int
	var count int
	var column string
	var order string
	var options string
	var err error
	qs := &QuerySettings{}

	startArg := args.Get("start")
	if startArg == "" {
		start = 0
	} else {
		start, err = strconv.Atoi(startArg)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	countArg := args.Get("count")
	if countArg == "" {
		count = 0
	} else {
		count, err = strconv.Atoi(countArg)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	fieldArg := args.Get("field")
	if fieldArg == "" {
		column = col
	} else {
		match, err := regexp.MatchString("(?i)^[a-z_][a-z0-9_]*$", fieldArg)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if match {
			column = fieldArg
		} else {
			return nil, errors.Errorf("Invalid field name")
		}
	}

	orderArg := args.Get("order")
	if orderArg == "" {
		orderArg = ord
	}
	if orderArg == ASC {
		order = "ASC"
	} else if orderArg == DESC {
		order = "DESC"
	} else {
		return nil, errors.Errorf("Invalid order argument %s", orderArg)
	}

	if column != "" {
		options = fmt.Sprintf("ORDER BY %s %s", column, order)
	} else {
		options = ""
	}

	if count > 0 {
		options = fmt.Sprintf(" %s LIMIT %d OFFSET %d", options, count, start)
	}

	qs.Start = start
	qs.Count = count
	qs.Field = column
	qs.Order = order
	qs.Compiled = options

	return qs, nil
}
