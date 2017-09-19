export const callbackify = (verify) => 
        (...args) => 
            verify(...args.slice(0, -1))
                .then(r => args[args.length - 1](null, Array.isArray(r) ? r[0] : r, Array.isArray(r) ? r[1] : undefined), 
                        e => args[args.length - 1](e))
                